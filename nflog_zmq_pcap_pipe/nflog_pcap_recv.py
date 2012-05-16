#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

def main():
	import itertools as it, operator as op, functools as ft
	from time import sleep
	from collections import deque
	import os, logging, pcap, metrics, shaper

	import argparse
	parser = argparse.ArgumentParser(
		description='Receive pcap stream from zeromq and push it to a fifo socket.')
	parser.add_argument('src', help='ZMQ socket address to bind to.')
	parser.add_argument('dst', help='Path to fifo to write stream to.')
	parser.add_argument('--rate-control',
		action='store_true', help='Handle possibly-compressed stream.')

	parser.add_argument('--buffer-interface',
		help='ZMQ socket to access traffic-buffer interface.'
			' Upon receiving request on it, pcap dump of'
				' a traffic will be generated and sent as a response.')
	parser.add_argument('--buffer-window',
		type=float, metavar='MiB', help='Amount of last traffic to keep buffered.')
	parser.add_argument('--buffer-timeout', default=1.0,
		type=float, metavar='s', help='Timeout for sending buffered stuff (default: %(default)s).')

	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	metrics.add_statsd_optz(parser)
	optz = parser.parse_args()

	logging.basicConfig(
		level=logging.DEBUG if optz.debug else logging.WARNING,
		logfmt='%(asctime)s :: %(levelname)s :: %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = logging.getLogger('pcap_recv')

	optz.reopen = True # only fifo dst for now
	if optz.buffer_window:
		optz.buffer_window = optz.buffer_window * 2**20

	statsd = metrics.statsd_from_optz(optz)

	if optz.rate_control:
		shaper = shaper.decompress_pipe()
		next(shaper)
	else: shaper = None

	import zmq
	context = zmq.Context()

	src = bif = None
	try:
		src = context.socket(zmq.PULL)
		src.bind(optz.src)
		zmq_poll = zmq.core.Poller()
		zmq_poll.register(src, zmq.POLLIN)

		if optz.buffer_interface and optz.buffer_window:
			def bif_init():
				bif = context.socket(zmq.REP)
				bif.setsockopt(zmq.LINGER, 0)
				bif.bind(optz.buffer_interface)
				for k in zmq.RCVTIMEO, zmq.SNDTIMEO:
					bif.setsockopt(k, int(optz.buffer_timeout * 1e3))
				return bif
			bif_buff, bif_buff_len, bif = deque(), 0, bif_init()
			zmq_poll.register(bif, zmq.POLLIN)

		buff = None

		while True:
			with open(optz.dst, 'wb', 0) as dst:
				pcap_dst = pcap.writer(dst.write)
				next(pcap_dst)
				log.debug('(Re-)opened destination path')

				while True:
					if not buff:
						if bif in it.imap(op.itemgetter(0), zmq_poll.poll()):
							# Break from main activity to send traffic dump
							pcap_bif = pcap.writer(ft.partial(bif.send, flags=zmq.SNDMORE))
							try:
								bif.recv() # contents aren't used
								next(pcap_bif)
								for pkt_len, pkt in bif_buff: pcap_bif.send(pkt)
								bif.send('')
							except zmq.ZMQError as err:
								if err.errno != zmq.EAGAIN: raise
								zmq_poll.unregister(bif)
								bif.close()
								bif = bif_init()
								zmq_poll.register(bif, zmq.POLLIN)
							finally: del pcap_bif
							continue

						buff = ''.join(src.recv_multipart())

						if statsd:
							statsd.send('raw_in.pkt')
							statsd.send('raw_in.bytes', len(buff))
						buff = shaper.send(buff) if shaper else [buff]

					try:
						buff_len = 0
						if bif: bif_tmp = list()
						for pkt in buff:
							pkt_len = pcap_dst.send(pkt)
							buff_len += pkt_len
							if bif: bif_tmp.append((pkt_len, pkt))
					except IOError: break

					if bif:
						bif_buff.extend(bif_tmp)
						del bif_tmp
						bif_buff_len += buff_len
						while bif_buff and bif_buff_len >= optz.buffer_window:
							pkt_len, pkt = bif_buff.popleft()
							bif_buff_len -= pkt_len

					if statsd:
						statsd.send('raw_out.pkt', len(buff))
						statsd.send('raw_out.bytes', buff_len)
					buff = None

			if not optz.reopen: break
			sleep(1)

	finally:
		if src: src.close()
		if bif: bif.close()
		log.debug('Finishing')
		context.term()

if __name__ == '__main__': main()
