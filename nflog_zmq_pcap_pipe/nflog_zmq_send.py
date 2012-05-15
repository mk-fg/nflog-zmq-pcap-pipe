#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

def main():
	from contextlib import closing
	import os, logging, nflog, pcap, metrics, shaper

	import argparse
	parser = argparse.ArgumentParser(description='Pipe nflog packet stream to zeromq.')
	parser.add_argument('src', help='Comma-separated list of nflog groups to receive.')
	parser.add_argument('dst', help='ZMQ socket address to send data to.')
	parser.add_argument('-u', '--user', help='User name to drop privileges to.')

	parser.add_argument('--libnflog-nlbufsiz',
		type=float, metavar='MiB', default=10.0,
		help='Netlink socket buffer size ("nlbufsiz", default: %(default)s).')
	parser.add_argument('--libnflog-qthresh',
		type=int, metavar='packets',
		help='NFLOG queue kernel-to-userspace'
			' packet-count flush threshold ("qthresh", default: nlbufsiz * 100).')
	parser.add_argument('--libnflog-timeout',
		type=float, metavar='seconds',
		help='NFLOG queue kernel-to-userspace'
			' flush timeout ("timeout", default: nlbufsiz / 5).')
	parser.add_argument('--zmq-buffer',
		type=int, metavar='msg_count',
		help='ZMQ_HWM for the socket - number of packets to'
			' buffer in RAM before blocking (default: qthresh / 10).')

	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')

	shaper.add_compress_optz(parser)
	metrics.add_statsd_optz(parser)
	optz = parser.parse_args()

	logging.basicConfig(
		level=logging.DEBUG if optz.debug else logging.WARNING,
		logfmt='%(asctime)s :: %(levelname)s :: %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = logging.getLogger('pcap_send')

	if optz.libnflog_qthresh is None:
		optz.libnflog_qthresh = int(optz.libnflog_nlbufsiz * 100)
	if optz.libnflog_timeout is None:
		optz.libnflog_timeout = int(optz.libnflog_nlbufsiz / 5.0)
	if optz.zmq_buffer is None:
		optz.zmq_buffer = int(optz.libnflog_qthresh / 10.0)

	src = nflog.nflog_generator(
		map(int, optz.src.split(',')),
		qthresh=max(1, optz.libnflog_qthresh),
		timeout=optz.libnflog_timeout,
		nlbufsiz=int(optz.libnflog_nlbufsiz * 2**20),
		extra_attrs=['len', 'ts'] )
	next(src) # no use for polling here

	if optz.user:
		import pwd
		optz.user = pwd.getpwnam(optz.user)
		os.setresgid(*[optz.user.pw_uid]*3)
		os.setresuid(*[optz.user.pw_gid]*3)

	statsd = metrics.statsd_from_optz(optz)
	shaper = shaper.compress_pipe_from_optz(optz)

	import zmq
	context = zmq.Context()

	try:
		with closing(context.socket(zmq.PUSH)) as dst:
			dst.setsockopt(zmq.HWM, optz.zmq_buffer)
			dst.setsockopt(zmq.LINGER, 0) # it's lossy either way
			dst.connect(optz.dst)

			log.debug('Entering NFLOG reader loop')
			for pkt, pkt_len, ts in src:
				if pkt is None: continue
				if statsd:
					statsd.send('raw_in.pkt')
					statsd.send(('raw_in.bytes', len(pkt)))

				pkt = pcap.construct(pkt, pkt_len=pkt_len, ts=ts)
				if shaper:
					pkt = shaper.send(pkt)
					if pkt is None: continue

				try: dst.send(pkt, zmq.NOBLOCK)
				except zmq.ZMQError as err:
					if err.errno != zmq.EAGAIN: raise

	finally:
		log.debug('Finishing')
		context.term()

if __name__ == '__main__': main()
