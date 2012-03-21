#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

def main():
	import argparse
	parser = argparse.ArgumentParser(
		description='Receive pcap stream from UDP and push it to a fifo socket.')
	parser.add_argument('src', help='ZMQ socket address to bind to.')
	parser.add_argument('dst', help='Path to fifo to write stream to.')
	optz = parser.parse_args()

	optz.reopen = True # only fifo dst for now

	import zmq

	context = zmq.Context()
	src = context.socket(zmq.PULL)
	src.bind(optz.src)

	while True:
		try:
			with open(optz.dst, 'wb') as dst:
				pkt = src.recv()
				dst.write(pkt)
		except OSError as err:
			if err.errno == errno.ENOENT: break
		if not optz.reopen: break
		sleep(1)
