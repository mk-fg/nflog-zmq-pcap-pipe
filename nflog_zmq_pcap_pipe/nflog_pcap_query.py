#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

def main():
	from contextlib import closing
	import os, sys, logging

	import argparse
	parser = argparse.ArgumentParser(
		description='Query nflog_pcap_recv daemon for buffered packets.')
	parser.add_argument('bif', help='ZMQ socket address to query.')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args()

	logging.basicConfig(
		level=logging.DEBUG if optz.debug else logging.WARNING,
		logfmt='%(asctime)s :: %(levelname)s :: %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = logging.getLogger('pcap_query')

	import zmq
	context = zmq.Context()

	try:
		with closing(context.socket(zmq.REQ)) as bif:
			log.debug('Sending request')
			bif.connect(optz.bif)
			bif.send('q')
			log.debug('Request sent')

			sys.stdout.write(bif.recv())
			while bif.getsockopt(zmq.RCVMORE):
				sys.stdout.write(bif.recv())

	finally:
		log.debug('Finishing')
		context.term()
