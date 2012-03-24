#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function


def pipe(cb, win, lwm, hwm, log):
	from time import time
	from zlib import compressobj

	if not lwm and not hwm: win = None
	else:
		bs, ts, rate = 0, time(), 0
		buff, comp = bytearray(win + 65535), None
	send = True

	while True:
		pkt = yield

		if win and bs > win:
			ts_now = time()
			rate = bs / (ts_now - ts)
			# log.debug('Rate: {:.2f} MiB/s'.format(rate / 2**20))

			if hwm and rate > hwm:
				# TODO: send at least some part of them
				log.warn('Dropping packets due to hwm (rate: {:.2f})'.format(rate / 2**20))
				send = None
			else:
				if send is False: cb('\x01' + bytes(buff[:bs]) + comp.flush())
				if lwm and rate > lwm:
					comp = compressobj()
					send = False
				else: send = True

			bs, ts = 0, ts_now

		if send: cb('\x00' + pkt)
		elif send is None: pass # drop packet
		else: # compress packet
			pkt = comp.compress(pkt)
			buff[bs:] = pkt

		if win: bs += len(pkt)


def main():
	import argparse
	parser = argparse.ArgumentParser(description='Pipe nflog packet stream to zeromq.')
	parser.add_argument('src', help='Comma-separated list of nflog groups to receive.')
	parser.add_argument('dst', help='ZMQ socket address to send data to.')
	parser.add_argument('-u', '--user', help='User name to drop privileges to.')

	parser.add_argument('--lwm',
		type=float, metavar='MiB/s', default=1.0,
		help='Low watermark - gzip packets after MiB/s'
			' (on the output to zmq) exceeds this value (default: %(default)s, 0 - disable).')
	parser.add_argument('--hwm',
		type=float, metavar='MiB/s', default=5.0,
		help='High watermark - drop packets after MiB/s'
			' (on the output to zmq) exceeds this value (default: %(default)s, 0 - disable).')
	parser.add_argument('--wm-interval',
		type=float, metavar='MiB',
		help='After how many MiB throughput gets recalculated,'
			' checked and (possibly) compressed (default: max(2 * hwm, 4 * lwm)).')

	parser.add_argument('--netlink-buffer',
		type=float, metavar='MiB', default=2.0,
		help='Netlink socket buffer size ("nlbufsiz", default: %(default)s).')
	parser.add_argument('--zmq-buffer',
		type=int, metavar='msg_count', default=30,
		help='ZMQ_HWM for the socket - number of packets to'
			' buffer in RAM before dropping (default: %(default)s).')

	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args()

	from contextlib import closing
	import os, errno, logging, nflog, pcap

	logging.basicConfig(
		level=logging.DEBUG if optz.debug else logging.WARNING,
		logfmt='%(asctime)s :: %(levelname)s :: %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = logging.getLogger('pcap_send')

	optz.lwm *= 2**20
	optz.hwm *= 2**20
	if optz.hwm and optz.lwm > optz.hwm: parser.error('hwm must be > than lwm')
	if optz.wm_interval is None:
		optz.wm_interval = max(optz.hwm * 2, optz.lwm * 4)
	else: optz.wm_interval *= 2**20

	src = nflog.nflog_generator(
		map(int, optz.src.split(',')),
		nlbufsiz=int(optz.netlink_buffer * 2**20) )
	next(src) # no use for polling here

	if optz.user:
		import pwd
		uid, gid = op.attrgetter('pw_uid', 'pw_gid')(pwd.getpwnam(optz.user))
		os.setresgid(*[gid]*3)
		os.setresuid(*[uid]*3)

	import zmq
	context = zmq.Context()

	try:
		with closing(context.socket(zmq.PUSH)) as dst:
			dst.setsockopt(zmq.HWM, optz.zmq_buffer)
			dst.setsockopt(zmq.LINGER, 0) # it's lossy either way
			dst.connect(optz.dst)

			def send_zmq(msg, dst=dst):
				try: dst.send(msg, zmq.NOBLOCK)
				except zmq.ZMQError as err:
					if err.errno != errno.EAGAIN: raise

			queue = pipe( send_zmq, log=log,
				win=int(optz.wm_interval), lwm=optz.lwm, hwm=optz.hwm )
			next(queue)

			log.debug('Entering NFLOG reader loop')
			for pkt in src:
				if pkt is None: continue
				queue.send(pcap.construct(pkt))

	finally:
		log.debug('Finishing')
		context.term()

if __name__ == '__main__': main()
