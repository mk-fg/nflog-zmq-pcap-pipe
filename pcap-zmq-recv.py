#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

####################

# Must be the same on sender/receiver
pcap_header = ( 'd4c3b2a102000400a0ab'
	'ffff000000000000010065000000' ).decode('hex')

####################


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
	import errno, logging

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
					log.debug('(Re-)opened destination path')
					dst.write(pcap_header)

					while True:
						pkt = src.recv()
						while src.getsockopt(zmq.RCVMORE): pkt += src.recv()
						dst.write(decompress(pkt[1:]) if pkt[0] == '\x01' else pkt[1:])
			except OSError as err:
				if err.errno == errno.ENOENT: break
			if not optz.reopen: break
			sleep(1)

	log.debug('Finishing')
	context.term()

if __name__ == '__main__': main()
