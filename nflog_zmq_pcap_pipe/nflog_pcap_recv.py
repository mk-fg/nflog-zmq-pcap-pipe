#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

def main():
	from contextlib import closing
	from time import sleep
	import os, logging, pcap, metrics, shaper

	import argparse
	parser = argparse.ArgumentParser(
		description='Receive pcap stream from zeromq and push it to a fifo socket.')
	parser.add_argument('src', help='ZMQ socket address to bind to.')
	parser.add_argument('dst', help='Path to fifo to write stream to.')
	parser.add_argument('--rate-control',
		action='store_true', help='Handle possibly-compressed stream.')
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

	if optz.rate_control:
		shaper = shaper.decompress_pipe()
		next(shaper)
	else: shaper = None

	import zmq
	context = zmq.Context()

	try:
		with closing(context.socket(zmq.PULL)) as src:
			src.bind(optz.src)
			buff = None

			while True:
				with open(optz.dst, 'wb', 0) as dst:
					pcap_dst = pcap.writer(dst)
					next(pcap_dst)
					log.debug('(Re-)opened destination path')

					while True:
						if not buff:
							buff = src.recv()
							while src.getsockopt(zmq.RCVMORE): buff += src.recv()

							if statsd:
								statsd.send('raw_in.pkt')
								statsd.send('raw_in.bytes', len(buff))
							buff = shaper.send(buff) if shaper else [buff]

						try:
							pkt_len = 0
							for pkt in buff: pkt_len += pcap_dst.send(pkt)
						except IOError: break

						if statsd:
							statsd.send('raw_out.pkt', len(buff))
							statsd.send('raw_out.bytes', pkt_len)
						buff = None

				if not optz.reopen: break
				sleep(1)

	finally:
		log.debug('Finishing')
		context.term()

if __name__ == '__main__': main()
