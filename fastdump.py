# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import socket


chunk = 2**10 # 1 KiB
prefix_fmt = '!IHI'


def send(dst, seq_start=0, chunk=chunk, prefix_fmt=prefix_fmt):
	from struct import pack, calcsize

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	chunk -= calcsize(prefix_fmt)

	for seq in it.chain.from_iterable(
			xrange(seq_start, seq) for seq in it.repeat(2**30) ):
		pkt = yield
		pkt_len, n = len(pkt), 0
		while n < pkt_len:
			sock.sendto(pack(prefix_fmt, seq, n, pkt_len) + pkt[n:n+chunk], dst)
			n += chunk


def recv( bind, chunk=chunk,
		max_gap=1000, pkt_max=100 * 2**10, prefix_fmt=prefix_fmt ):
	from struct import unpack_from, calcsize
	from heapq import heappop, heappush

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(bind)
	heap, prefix_len = list(), calcsize(prefix_fmt)
	pkt = bytearray(pkt_max)

	# Fetch one packet to get the current seq
	buff, addr = sock.recvfrom(chunk)
	xseq, xn, pkt_len = unpack_from(prefix_fmt, buff)
	if xn != 0: xseq, xn = xseq + 1, 0

	while True:
		seq, n, pkt_len = unpack_from(prefix_fmt, buff)

		if seq == xseq and n == xn: # consume
			pkt[xn:] = buff[prefix_len:]
			xn += len(buff) - prefix_len
			if xn == pkt_len: # fully assembled packet
				yield pkt[0:pkt_len]
				# yield xseq, pkt[0:pkt_len]
				xseq, xn = xseq + 1, 0 # not necessarily same as heap[0]
			try: buff = heappop(heap) # TODO: just peek?
			except IndexError: pass
			else: continue

		elif abs(seq - xseq) > max_gap: # give up on pkt
			# TODO: log the loss somehow
			heappush(heap, buff)
			xseq_min, xn = xseq, None
			try:
				while xseq < xseq_min or xn != 0: # to ignore leftovers of first seq there (current?)
					buff = heappop(heap)
					xseq, xn, pkt_len = unpack_from(prefix_fmt, buff)
				continue
			except IndexError: # no seq-starters? meh
				xseq, xn = xseq_min + 1, 0

		elif seq >= xseq: # buffer for the future (pkt reorder/loss)
			heappush(heap, buff)

		buff, addr = sock.recvfrom(chunk)


if __name__ == '__main__':
	from hashlib import sha1
	import sys

	def sender(start):
		from random import randint

		src = open('/dev/urandom', 'rb')
		sock = send(('127.0.0.1', 12345), seq_start=start)
		next(sock)

		for i in xrange(10):
			pkt_len = randint(10 * 2**10, 63 * 2**10) # 10-63 KiB
			pkt = src.read(pkt_len)
			print(sha1(pkt).hexdigest())
			sock.send(pkt)

	def receiver():
		sock = recv(('127.0.0.1', 12345), max_gap=10)
		for pkt in sock: print(sha1(pkt).hexdigest())

	if len(sys.argv) > 1: sender(int(sys.argv[1]))
	else: receiver()
