# -*- coding: utf-8 -*-
from __future__ import print_function

import logging
log = logging.getLogger('compressor')


def add_compress_optz(parser, always_enabled=False):
	if not always_enabled:
		parser.add_argument('--rate-control', action='store_true',
			help='Enable rate control and compression of data before it is sent.')
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

def compress_pipe_from_optz(optz, always_enabled=False):
	if not always_enabled and not optz.rate_control: return None
	optz.lwm *= 2**20
	optz.hwm *= 2**20
	if optz.hwm and optz.lwm > optz.hwm: parser.error('hwm must be > than lwm')
	if optz.wm_interval is None:
		optz.wm_interval = max(optz.hwm * 2, optz.lwm * 4)
	else: optz.wm_interval *= 2**20
	pipe = compress_pipe(
		win=int(optz.wm_interval),
		lwm=optz.lwm, hwm=optz.hwm, log=log )
	next(pipe)
	return pipe


def compress_pipe(win, lwm, hwm, log, pkt_len_fmt='!I'):
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


def decompress_pipe(pkt_len_fmt='!I'):
	from struct import unpack, calcsize
	from zlib import decompress
	pkt_len_size = calcsize(pkt_len_fmt)
	pkt_out = list()
	while True:
		pkt = yield pkt_out
		pkt_out = list()
		if pkt[0] == '\x01':
			pkt = decompress(pkt[1:])
			pos, pos_max = 0, len(pkt)
			while pos != pos_max:
				pkt_len, = unpack(pkt_len_fmt, pkt[pos:pos+pkt_len_size])
				pos += pkt_len_size + pkt_len
				pkt_out.append(pkt[pos - pkt_len:pos])
		else: pkt_out.append(pkt[1:])
