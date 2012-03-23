# -*- coding: utf-8 -*-
from __future__ import print_function

'ctypes wrapper for libnetfilter_log'

import itertools as it, operator as op, functools as ft
import ctypes, socket


class NFLogError(Exception): pass

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
	return libnflog


def nflog_generator(qids):
	'''Generator that yields:
		- netlink fd that can be poll'ed on first iteration
		- on all subsequent iterations, it does recv() on that fd,
			returning either None (if no packet can be assembled yet)
			or captured packet payload.'''

	libnflog = libnflog_init()
	handle = libnflog.nflog_open()
	libnflog.nflog_unbind_pf(handle, socket.AF_INET)
	libnflog.nflog_unbind_pf(handle, socket.AF_INET6)
	libnflog.nflog_bind_pf(handle, socket.AF_INET)
	libnflog.nflog_bind_pf(handle, socket.AF_INET6)

	cb_result = list() # pity there's no "nonlocal" in py2.X
	def callback( qh, nfmsg, nfad, res=cb_result,
			pkt=ctypes.POINTER(ctypes.c_char)() ):
		pkt_len = libnflog.nflog_get_payload(nfad, ctypes.byref(pkt))
		res.append(pkt[:pkt_len])

	nflog_cb_t = ctypes.CFUNCTYPE( ctypes.c_void_p,
		ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p )
	c_cb = nflog_cb_t(callback)

	for qid in qids:
		qh = libnflog.nflog_bind_group(handle, qid)
		libnflog.nflog_set_mode(qh, 0x2, 0xffff) # NFULNL_COPY_PACKET
		libnflog.nflog_callback_register(qh, c_cb)

	fd = libnflog.nflog_fd(handle)
	def handle_packet( fd=fd, handle=handle,
			buff=ctypes.create_string_buffer(256) ):
		libnflog.nflog_handle_packet(
			handle, buff, libnflog.recv(fd, buff, 256, 0) )

	res = fd # first yield is an fd, for poll(), if needed
	while True:
		yield res
		handle_packet()
		try: res = cb_result.pop()
		except IndexError: res = None


if __name__ == '__main__':
	src = nflog_generator([0, 1])
	fd = next(src)
	for pkt in src:
		if pkt is None: continue
		print('Got packet, len: {}'.format(len(pkt)))
