#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

def main():
	import argparse
	parser = argparse.ArgumentParser(description='Pipe pcap stream via UDP.')
	parser.add_argument('src', help='Path to file/fifo to read stream from.')
	parser.add_argument('dst', help='ZMQ socket address to send data to.')
	parser.add_argument('--reopen', action='store_true',
		help='Keep re-opening the path on eof or any read errors (as long as it exists).'
			' Used implicitly for FIFO sockets (to allow writer process to be restarted).')
	parser.add_argument('-b', '--buffer', action='store', type=int, default=100,
		help='ZMQ_HWM for the socket - number of packets to'
			' buffer in RAM before dropping (default: %(default)s).')
	optz = parser.parse_args()

	import os, sys, stat, errno
	from struct import unpack
	from time import sleep

	optz.reopen = stat.ISFIFO(os.stat(optz.path).st_mode)
	pcap_hdr = 8 + 4 + 4 # pcap_timeval 2xint32, caplen uint32, len uint32

	import zmq
	context = zmq.Context()
	dst = context.socket(zmq.PUSH)
	dst.setsockopt(zmq.ZMQ_HWM, optz.buffer)
	dst.connect(optz.dst)

	while True:
		try:
			with open(optz.src, 'rb') as src:
				pkt_hdr = src.read(pcap_hdr)
				pkt_len = unpack('=I', buff[8:12])
				if dst.poll(0): # don't block, just discard the packet
					dst.send(pkt_hdr + src.read(pkt_len))
		except OSError as err:
			if err.errno == errno.ENOENT: break
		if not optz.reopen: break
		sleep(1)

if __name__ == '__main__': main()
