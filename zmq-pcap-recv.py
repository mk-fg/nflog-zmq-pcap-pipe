#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function


def main():
	from contextlib import closing
	from time import sleep
	from zlib import decompress
	from struct import unpack, calcsize
	import os, logging, pcap, metrics

	import argparse
	parser = argparse.ArgumentParser(
		description='Receive pcap stream from zeromq and push it to a fifo socket.')
	parser.add_argument('src', help='ZMQ socket address to bind to.')
	parser.add_argument('dst', help='Path to fifo to write stream to.')

	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')

	metrics.add_statsd_optz(parser)
	optz = parser.parse_args()

	logging.basicConfig(
		level=logging.DEBUG if optz.debug else logging.WARNING,
		logfmt='%(asctime)s :: %(levelname)s :: %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = logging.getLogger('pcap_recv')

	optz.reopen = True # only fifo dst for now
	statsd = metrics.statsd_from_optz(optz)

	import zmq
	context = zmq.Context()

	pkt_len_fmt = '!I'
	pkt_len_size = calcsize(pkt_len_fmt)

	with closing(context.socket(zmq.PULL)) as src:
		src.bind(optz.src)

		while True:
			try:
				with open(optz.dst, 'wb') as dst:
					os.dup2(dst.fileno(), 1)
					pcap_dst = pcap.writer()
					next(pcap_dst)
					log.debug('(Re-)opened destination path')

					while True:
						buff = src.recv()
						while src.getsockopt(zmq.RCVMORE): buff += src.recv()
						if statsd: statsd.send('pipe_in')
						if buff[0] == '\x01':
							buff = decompress(buff[1:])
							pos, pos_max = 0, len(buff)
							while pos != pos_max:
								pkt_len, = unpack(pkt_len_fmt, buff[pos:pos+pkt_len_size])
								pos += pkt_len_size + pkt_len
								pcap_dst.send(buff[pos - pkt_len:pos])
								if statsd: statsd.send('raw_out')
						else:
							pcap_dst.send(buff[1:])
							if statsd: statsd.send('raw_out')
			except pcap.PcapError as err: log.exception('Error from libpcap')
			if not optz.reopen: break
			sleep(1)

	log.debug('Finishing')
	context.term()

if __name__ == '__main__': main()