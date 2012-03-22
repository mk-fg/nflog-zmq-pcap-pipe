#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function


def pipe(src, dst, win, lwm, hwm, log):
	from time import time
	from zlib import compressobj

	if not lwm and not hwm: win = None
	else:
		bs, ts, rate = 0, time(), 0
		buff, comp = bytearray(win + 65535), None
	send = True
	pcap_hdr_len = 8 + 4 + 4 # pcap_timeval 2xint32, caplen uint32, len uint32

	for pkt in src:

		if win and bs > win:
			ts_now = time()
			rate = bs / (ts_now - ts)
			# log.debug('Rate: {:.2f} MiB/s'.format(rate / 2**20))

			if hwm and rate > hwm:
				# TODO: send at least some part of them
				log.warn('Dropping packets due to hwm (rate: {:.2f})'.format(rate / 2**20))
				send = None
			else:
				if send is False: dst('\x01' + bytes(buff[:bs]) + comp.flush())
				if lwm and rate > lwm:
					comp = compressobj()
					send = False
				else: send = True

			bs, ts = 0, ts_now

		if send: dst('\x00' + pkt)
		elif send is None: pass # drop packet
		else: # compress packet
			pkt = comp.compress(pkt)
			buff[bs:] = pkt

		if win: bs += len(pkt)


def main():
	import argparse
	parser = argparse.ArgumentParser(description='Pipe pcap stream via zeromq.')
	parser.add_argument('src', help='Path to file/fifo to read stream from.')
	parser.add_argument('dst', help='ZMQ socket address to send data to.')
	parser.add_argument('--reopen', action='store_true',
		help='Keep re-opening the path on eof or any read errors (as long as it exists).'
			' Used implicitly for FIFO sockets (to allow writer process to be restarted).')

	parser.add_argument('--lwm', type=float, default=1.0,
		help='Low watermark - gzip packets after MiB/s'
			' (on the output to zmq) exceeds this value (default: %(default)s, 0 - disable).')
	parser.add_argument('--hwm', type=float, default=5.0,
		help='High watermark - drop packets after MiB/s'
			' (on the output to zmq) exceeds this value (default: %(default)s, 0 - disable).')
	parser.add_argument('--wm-interval', type=float, metavar='MiB',
		help='After how many MiB throughput gets recalculated,'
			' checked and (possibly) compressed (default: max(2 * hwm, 4 * lwm)).')

	parser.add_argument('--zmq-buffer', type=int, default=100,
		help='ZMQ_HWM for the socket - number of packets to'
			' buffer in RAM before dropping (default: %(default)s).')

	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args()

	from contextlib import closing
	from time import sleep
	import os, stat, errno, logging, pcap

	logging.basicConfig(
		level=logging.DEBUG if optz.debug else logging.WARNING,
		logfmt='%(asctime)s :: %(levelname)s :: %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S' )
	log = logging.getLogger('pcap_send')

	optz.lwm *= 2**20
	optz.hwm *= 2**20
	if optz.hwm and optz.lwm > optz.hwm: parser.error('hwm must be > than lwm')
	if optz.wm_interval is None:
		optz.wm_interval = max(optz.hwm * 2, optz.lwm * 4)
	else: optz.wm_interval *= 2**20
	if optz.reopen is None:
		optz.reopen = stat.S_ISFIFO(os.stat(optz.src).st_mode)

	import zmq
	context = zmq.Context()

	with closing(context.socket(zmq.PUSH)) as dst:
		dst.setsockopt(zmq.HWM, optz.zmq_buffer)
		dst.setsockopt(zmq.LINGER, 0) # it's lossy either way
		dst.connect(optz.dst)

		def send(msg, dst=dst):
			try: dst.send(msg, zmq.NOBLOCK)
			except zmq.ZMQError as err:
				if err.errno != errno.EAGAIN: raise

		while True:
			try:
				with open(optz.src, 'rb') as src:
					os.dup2(src.fileno(), 0) # replace stdin
					pcap_src = pcap.reader()
					log.debug('(Re-)opened source path')
					pipe( pcap_src, send,
						win=int(optz.wm_interval),
						lwm=optz.lwm, hwm=optz.hwm, log=log )
			except pcap.PcapError as err: log.exception('Error from libpcap')
			if not optz.reopen: break
			sleep(1)

	log.debug('Finishing')
	context.term()

if __name__ == '__main__': main()
