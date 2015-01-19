# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from time import time, timezone
from collections import namedtuple
import xdrlib, logging

'Simple pcap generator'


Packet = namedtuple('Packet', 'ts_s ts_us len dump')


def construct(pkt, pkt_len=None, ts=None):
	ts = ts or time()
	ts_sec = int(ts)
	ts_usec = int((ts - ts_sec) * 1e6)
	metadata = [ts_sec, ts_usec, pkt_len or 0]
	dump = xdrlib.Packer()
	try:
		dump.pack_farray(3, metadata, dump.pack_uint)
		dump.pack_bytes(pkt)
	except xdrlib.Error as err:
		logging.getLogger('pcap_serializer')\
			.exception( 'Failed to serialize packet (metadata: %r,'
				' bytes: %s), skipping: %s %s', metadata, len(pkt), type(err), err )
		return
	return dump.get_buffer()


def loads(dump):
	dump = xdrlib.Unpacker(dump)
	ts_s, ts_us, pkt_len = dump.unpack_farray(3, dump.unpack_uint)
	pkt = dump.unpack_bytes()
	dump.done()
	return Packet(ts_s, ts_us, pkt_len, pkt)


def writer(write, opaque=True, utc=True, snaplen=65535):
	from struct import pack
	write(pack( '=IHHiIII',
		0xa1b2c3d4, 2, 4, 0 if utc else timezone, 0, snaplen, 12 ))
	pkt_out = None
	while True:
		pkt = yield pkt_out
		pkt = loads(pkt) if opaque else pkt
		pkt_len = len(pkt.dump)
		pkt = pack('=IIII', pkt.ts_s, pkt.ts_us, pkt_len, pkt.len or pkt_len), pkt.dump
		pkt_out = sum(it.imap(len, pkt))
		for pkt in pkt: write(pkt)
