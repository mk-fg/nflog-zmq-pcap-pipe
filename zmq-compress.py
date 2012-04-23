#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function


def pipe(win, lwm, hwm, log, pkt_len_fmt='!I'):
	from time import time
	from zlib import compressobj
	from struct import pack

	if not lwm and not hwm: win = None
	else:
		bs, ts, rate = 0, time(), 0
		buff, comp = bytearray(win + 65535), None
	send = True

	pkt_out = None
	while True:
		pkt = yield pkt_out
		pkt_out = None

		if win and bs > win:
			ts_now = time()
			rate = bs / (ts_now - ts)
			# log.debug('Rate: {:.2f} MiB/s'.format(rate / 2**20))

			if hwm and rate > hwm:
				# TODO: send at least some part of them
				log.warn('Dropping packets due to hwm (rate: {:.2f})'.format(rate / 2**20))
				send = None
			else:
				if send is False: pkt_out = '\x01' + bytes(buff[:bs]) + comp.flush()
				if lwm and rate > lwm:
					# log.debug( 'lwm reached (rate: {:.2f}),'
					# 	' compressing packets'.format(rate / 2**20) )
					comp = compressobj()
					send = False
				else: send = True

			bs, ts = 0, ts_now

		if send: pkt_out = '\x00' + pkt
		elif send is None: pass # drop packet
		else: # compress packet
			pkt = comp.compress(pack(pkt_len_fmt, len(pkt)) + pkt)
			buff[bs:] = pkt

		if win: bs += len(pkt)


def main():
	from contextlib import closing
	import os, errno, logging, metrics

	import argparse
	parser = argparse.ArgumentParser(
		description='Compress or drop traffiic between two'
			' zmq sockets if its volume is above defined thresholds.')
	parser.add_argument('src', help='Receiving ZMQ socket address to bind to.')
	parser.add_argument('dst', help='ZMQ socket address to relay data to.')

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
	parser.add_argument('--zmq-buffer',
		type=int, metavar='msg_count', default=50,
		help='ZMQ_HWM for the sending socket - number of (possibly'
			' compressed) packets to buffer in RAM before blocking (default: %(default)s).')

	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')

	metrics.add_statsd_optz(parser)
	optz = parser.parse_args()

	logging.basicConfig(
		level=logging.DEBUG if optz.debug else logging.WARNING,
		logfmt='%(asctime)s :: %(levelname)s :: %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = logging.getLogger('zmq_compress')

	optz.lwm *= 2**20
	optz.hwm *= 2**20
	if optz.hwm and optz.lwm > optz.hwm: parser.error('hwm must be > than lwm')
	if optz.wm_interval is None:
		optz.wm_interval = max(optz.hwm * 2, optz.lwm * 4)
	else: optz.wm_interval *= 2**20

	statsd = metrics.statsd_from_optz(optz)
	compressor = pipe(
		win=int(optz.wm_interval),
		lwm=optz.lwm, hwm=optz.hwm, log=log )
	next(compressor)

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
					statsd.send('compress_in.pkt')
					statsd.send('compress_in.bytes', len(buff))

				pkt = compressor.send(buff)
				if pkt is None: continue

				try: dst.send(pkt, zmq.NOBLOCK)
				except zmq.ZMQError as err:
					if err.errno != errno.EAGAIN: raise
					continue # so zmq-dropped packets won't be counted in statsd

				if statsd:
					statsd.send('compress_out.pkt')
					statsd.send('compress_out.bytes', len(pkt))

	finally:
		log.debug('Finishing')
		context.term()

if __name__ == '__main__': main()
