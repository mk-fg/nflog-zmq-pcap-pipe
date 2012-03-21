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
	parser.add_argument('-b', '--buffer', type=int, default=100,
		help='ZMQ_HWM for the socket - number of packets to'
			' buffer in RAM before dropping (default: %(default)s).')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args()

	from contextlib import closing
	from struct import unpack
	from time import sleep
	import os, stat, errno, logging

	logging.basicConfig(
		level=logging.DEBUG if optz.debug else logging.WARNING,
		logfmt='%(asctime)s :: %(levelname)s :: %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = logging.getLogger('pcap_send')

	optz.reopen = stat.S_ISFIFO(os.stat(optz.src).st_mode)
	pcap_hdr = 8 + 4 + 4 # pcap_timeval 2xint32, caplen uint32, len uint32

	import zmq
	context = zmq.Context()

	with closing(context.socket(zmq.PUSH)) as dst:
		dst.setsockopt(zmq.HWM, optz.buffer)
		dst.setsockopt(zmq.LINGER, 0) # it's lossy either way
		dst.connect(optz.dst)

		while True:
			try:
				with open(optz.src, 'rb') as src:
					log.debug('(Re-)opened source path')
					while True:
						pkt_hdr = src.read(pcap_hdr)
						if not pkt_hdr: break
						pkt_len, = unpack('=I', pkt_hdr[8:12])
						dst.send(pkt_hdr + src.read(pkt_len), zmq.NOBLOCK)
			except OSError as err:
				if err.errno == errno.ENOENT: break
			if not optz.reopen: break
			sleep(1)
			break

	log.debug('Finishing')
	context.term()

if __name__ == '__main__': main()
