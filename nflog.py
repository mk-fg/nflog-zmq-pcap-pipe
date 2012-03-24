# -*- coding: utf-8 -*-
from __future__ import print_function

'ctypes wrapper for libnetfilter_log'

import itertools as it, operator as op, functools as ft
import ctypes, socket


class NFLogError(Exception): pass

class c_nflog_timeval(ctypes.Structure):
	_fields_ = [
		('tv_sec', ctypes.c_long),
		('tv_usec', ctypes.c_long) ]

def _chk_int(res, func, args, gt0=False):
	if res < 0: raise NFLogError()
	if gt0 and res == 0: raise NFLogError()
	return res


libnflog = None
def libnflog_init():
	global libnflog
	if not libnflog:
		libnflog = ctypes.CDLL('libnetfilter_log.so.1')

		libnflog.nflog_open.restype = ctypes.c_void_p
		libnflog.nflog_bind_group.restype = ctypes.c_void_p

		libnflog.nflog_unbind_pf.errcheck = _chk_int
		libnflog.nflog_bind_pf.errcheck = _chk_int
		libnflog.nflog_set_mode.errcheck = _chk_int
		libnflog.recv.errcheck = ft.partial(_chk_int, gt0=True)
		libnflog.nflog_get_payload.errcheck = _chk_int
		libnflog.nflog_get_timestamp.errcheck = _chk_int
	return libnflog


_cb_result = None # pity there's no "nonlocal" in py2.X

def nflog_generator(qids,
		pf=(socket.AF_INET, socket.AF_INET6),
		extra_attrs=None ):
	'''Generator that yields:
		- on first iteration - netlink fd that can be poll'ed
			or integrated into some event loop (twisted, gevent, ...)
		- on all subsequent iterations it does recv() on that fd,
			returning either None (if no packet can be assembled yet)
			or captured packet payload.'''
	global _cb_result

	libnflog = libnflog_init()
	handle = libnflog.nflog_open()

	for pf in (pf if not isinstance(pf, int) else [pf]):
		libnflog.nflog_unbind_pf(handle, pf)
		libnflog.nflog_bind_pf(handle, pf)

	if isinstance(extra_attrs, bytes): extra_attrs = [extra_attrs]

	def callback( qh, nfmsg, nfad, extra_attrs=extra_attrs,
			pkt=ctypes.pointer(ctypes.POINTER(ctypes.c_char)()),
			ts=ctypes.pointer(c_nflog_timeval()) ):
		global _cb_result
		try:
			pkt_len = libnflog.nflog_get_payload(nfad, pkt)
			_cb_result = pkt.contents[:pkt_len]
			if extra_attrs:
				_cb_result = [_cb_result]
				for attr in extra_attrs:
					if attr == 'len': _cb_result.append(pkt_len) # wtf4? just looks nicer than len(pkt)
					elif attr == 'ts':
						try: libnflog.nflog_get_timestamp(nfad, ts) # it fails 19/20, no idea why
						except NFLogError: _cb_result.append(None)
						else: _cb_result.append(ts.contents.tv_sec + ts.contents.tv_usec * 1e-6)
					else: raise NotImplementedError('Unknown nflog attribute: {}'.format(attr))
		except:
			_cb_result = StopIteration # breaks the generator
			raise

	nflog_cb_t = ctypes.CFUNCTYPE(
		ctypes.c_void_p, *[ctypes.POINTER(ctypes.c_void_p)]*3 )
	c_cb = nflog_cb_t(callback)

	for qid in (qids if not isinstance(qids, int) else [qids]):
		qh = libnflog.nflog_bind_group(handle, qid)
		libnflog.nflog_set_mode(qh, 0x2, 0xffff) # NFULNL_COPY_PACKET
		libnflog.nflog_callback_register(qh, c_cb)

	fd = libnflog.nflog_fd(handle)
	buff = ctypes.create_string_buffer(256)

	yield fd # yield fd for poll() on first iteration
	while True:
		_cb_result = None
		libnflog.nflog_handle_packet(
			handle, buff, libnflog.recv(fd, buff, 256, 0) )
		if _cb_result is StopIteration: raise _cb_result
		yield _cb_result


if __name__ == '__main__':
	src = nflog_generator([0, 1], extra_attrs=['len', 'ts'])
	fd = next(src)
	for pkt in src:
		if pkt is None: continue
		pkt, pkt_len, ts = pkt
		print('Got packet, len: {}, ts: {}'.format(pkt_len, ts))
		# print('Payload:', pkt.encode('hex'))
