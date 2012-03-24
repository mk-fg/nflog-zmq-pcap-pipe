#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function


def main():
	import argparse
	parser = argparse.ArgumentParser(
		description='Receive pcap stream from zeromq and push it to a fifo socket.')
	parser.add_argument('src', help='ZMQ socket address to bind to.')
	parser.add_argument('dst', help='Path to fifo to write stream to.')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args()

	from contextlib import closing
	from time import sleep
	from zlib import decompress
	import os, logging, pcap

	logging.basicConfig(
		level=logging.DEBUG if optz.debug else logging.WARNING,
		logfmt='%(asctime)s :: %(levelname)s :: %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = logging.getLogger('pcap_recv')

	optz.reopen = True # only fifo dst for now

	import zmq
	context = zmq.Context()

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
						pkt = src.recv()
						while src.getsockopt(zmq.RCVMORE): pkt += src.recv()
						pcap_dst.send(decompress(pkt[1:]) if pkt[0] == '\x01' else pkt[1:])
			except pcap.PcapError as err: log.exception('Error from libpcap')
			if not optz.reopen: break
			sleep(1)

	log.debug('Finishing')
	context.term()

if __name__ == '__main__': main()
