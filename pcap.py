# -*- coding: utf-8 -*-

'ctypes wrapper for libpcap'

import itertools as it, operator as op, functools as ft
import ctypes

class PcapError(Exception): pass

class pcap_timeval(ctypes.Structure):
	_fields_ = [
		('tv_sec', ctypes.c_int32),
		('tv_usec', ctypes.c_int32) ]
class pcap_pkthdr(ctypes.Structure):
	_fields_ = [
		('ts', pcap_timeval),
		('caplen', ctypes.c_uint32),
		('len', ctypes.c_uint32) ]

libpcap = ctypes.CDLL('libpcap.so.1')
libpcap.pcap_geterr.restype = ctypes.c_char_p
libpcap.pcap_open_offline.restype = ctypes.c_void_p
libpcap.pcap_open_dead.restype = ctypes.c_void_p
libpcap.pcap_dump_open.restype = ctypes.c_void_p
libpcap.pcap_next_ex.argtypes = ctypes.c_void_p,\
	ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),\
	ctypes.POINTER(ctypes.POINTER(ctypes.c_char))

def ReadCheck(pcap_t, err, func, args):
	if err == -1: raise PcapError(libpcap.pcap_geterr(pcap_t))
	elif err == -2: raise StopIteration()
	return err
def NullCheck(pcap_t, res, func, args):
	if not res: raise PcapError(libpcap.pcap_geterr(pcap_t))
	return res

def read(path):
	errbuff = ctypes.create_string_buffer(256)
	src = libpcap.pcap_open_offline(path, errbuff)
	if not src: raise PcapError(errbuff.value)
	try:
		libpcap.pcap_next_ex.errcheck = ft.partial(ReadCheck, src)
		pkt_hdr_p, pkt_p = ctypes.POINTER(pcap_pkthdr)(), ctypes.POINTER(ctypes.c_char)()
		while True:
			val = libpcap.pcap_next_ex(src, ctypes.byref(pkt_hdr_p), pkt_p)
			pkt_hdr = pkt_hdr_p.contents
			pkt = pkt_p[:pkt_hdr.caplen]
			yield pkt_hdr, pkt
	finally: libpcap.pcap_close(src)

def write(path):
	dst = libpcap.pcap_open_dead(0, 65535) # linktype=DLT_NULL, snaplen
	if not dst: raise PcapError

	libpcap.pcap_dump_open.errcheck = ft.partial(NullCheck, dst)
	dumper = libpcap.pcap_dump_open(dst, path)

	while True:
		pkt_hdr, pkt = yield
		libpcap.pcap_dump(dumper, ctypes.byref(pkt_hdr), pkt)
