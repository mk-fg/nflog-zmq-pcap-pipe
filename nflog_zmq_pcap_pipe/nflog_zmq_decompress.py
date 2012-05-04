#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function


def main():
	from contextlib import closing
	import os, errno, logging, metrics, shaper

	import argparse
	parser = argparse.ArgumentParser(
		description='Decompress traffic coming from zmq socket,'
			' if it is marked as compressed, and push to another socket.')
	parser.add_argument('src', help='Receiving ZMQ socket address to bind to.')
	parser.add_argument('dst', help='ZMQ socket address to relay data to.')
	parser.add_argument('--zmq-buffer',
		type=int, metavar='msg_count', default=50,
		help='ZMQ_HWM for the sending socket - number of'
			' packets to buffer in RAM before blocking (default: %(default)s).')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	metrics.add_statsd_optz(parser)
	optz = parser.parse_args()

	logging.basicConfig(
		level=logging.DEBUG if optz.debug else logging.WARNING,
		logfmt='%(asctime)s :: %(levelname)s :: %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = logging.getLogger('zmq_decompress')

	statsd = metrics.statsd_from_optz(optz)
	decompressor = shaper.decompress_pipe()
	next(decompressor)

	import zmq
	context = zmq.Context()

	try:
		with closing(context.socket(zmq.PULL)) as src,\
				closing(context.socket(zmq.PUSH)) as dst:
			src.bind(optz.src)
			dst.setsockopt(zmq.HWM, optz.zmq_buffer)
			dst.setsockopt(zmq.LINGER, 0) # it's lossy either way
			dst.connect(optz.dst)

			log.debug('Starting pipeline loop')
			while True:
				buff = src.recv()
				while src.getsockopt(zmq.RCVMORE): buff += src.recv()

				if statsd:
					statsd.send('decompress_in.pkt')
					statsd.send(('decompress_in.bytes', len(buff)))

				for pkt in decompressor.send(buff):
					try: dst.send(pkt, zmq.NOBLOCK)
					except zmq.ZMQError as err:
						if err.errno != errno.EAGAIN: raise
						continue # so zmq-dropped packets won't be counted in statsd

					if statsd:
						statsd.send('decompress_out.pkt')
						statsd.send(('decompress_out.bytes', len(pkt)))

	finally:
		log.debug('Finishing')
		context.term()

if __name__ == '__main__': main()
