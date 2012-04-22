# -*- coding: utf-8 -*-
from __future__ import print_function

'ctypes wrapper for libnetfilter_log'

import itertools as it, operator as op, functools as ft
import os, errno, ctypes, socket, logging

log = logging.getLogger('nflog')


class NFLogError(OSError): pass

class c_nflog_timeval(ctypes.Structure):
	_fields_ = [
		('tv_sec', ctypes.c_long),
		('tv_usec', ctypes.c_long) ]

def _chk_int(res, func, args, gt0=False):
	if res < 0 or (gt0 and res == 0):
		errno_ = ctypes.get_errno()
		raise NFLogError(errno_, os.strerror(errno_))
	return res


libnflog = None
def libnflog_init():
	global libnflog
	if not libnflog:
		libnflog = ctypes.CDLL('libnetfilter_log.so.1', use_errno=True)

		libnflog.nflog_open.restype = ctypes.c_void_p
		libnflog.nflog_bind_group.restype = ctypes.c_void_p

		libnflog.nflog_unbind_pf.errcheck = _chk_int
		libnflog.nflog_bind_pf.errcheck = _chk_int
		libnflog.nflog_set_mode.errcheck = _chk_int
		libnflog.nflog_set_qthresh.errcheck = _chk_int
		libnflog.nflog_set_timeout.errcheck = _chk_int
		libnflog.nflog_set_nlbufsiz.errcheck = _chk_int
		libnflog.recv.errcheck = ft.partial(_chk_int, gt0=True)
		libnflog.nflog_get_payload.errcheck = _chk_int
		libnflog.nflog_get_timestamp.errcheck = _chk_int
	return libnflog


_cb_result = None # pity there's no "nonlocal" in py2.X

def nflog_generator(qids,
		pf=(socket.AF_INET, socket.AF_INET6),
		qthresh=None, timeout=None, nlbufsiz=None, extra_attrs=None ):
	'''Generator that yields:
			- on first iteration - netlink fd that can be poll'ed
				or integrated into some event loop (twisted, gevent, ...).
				Also, that is the point where uid/gid/caps can be dropped.
			- on all subsequent iterations it does recv() on that fd,
				returning either None (if no packet can be assembled yet)
				or captured packet payload.
		qids: nflog group ids to bind to (nflog_bind_group)
		Keywords:
			pf: address families to pass to nflog_bind_pf
			extra_attrs: metadata to extract from captured packets,
				returned in a list after packet payload, in the same order
			qthresh (packets): set the maximum amount of logs in buffer for each group
			timeout (seconds): set the maximum time to push log buffer for this group
			nlbufsiz (bytes): set size of netlink socket buffer for the created queues'''
	global _cb_result

	libnflog = libnflog_init()
	handle = libnflog.nflog_open()

	for pf in (pf if not isinstance(pf, int) else [pf]):
		libnflog.nflog_unbind_pf(handle, pf)
		libnflog.nflog_bind_pf(handle, pf)

	if isinstance(extra_attrs, bytes): extra_attrs = [extra_attrs]

	def callback( qh, nfmsg, nfad, extra_attrs=extra_attrs,
			pkt=ctypes.pointer(ctypes.POINTER(ctypes.c_char)()),
			ts=ctypes.pointer(c_nflog_timeval()),
			ts_err_mask=frozenset([0, errno.EAGAIN]), result=None ):
		global _cb_result
		try:
			pkt_len = libnflog.nflog_get_payload(nfad, pkt)
			result = pkt.contents[:pkt_len]
			if extra_attrs:
				result = [result]
				for attr in extra_attrs:
					if attr == 'len': result.append(pkt_len) # wtf4? just looks nicer than len(pkt)
					elif attr == 'ts':
						# Fails quite often (EAGAIN, SUCCESS, ...), no idea why
						try: libnflog.nflog_get_timestamp(nfad, ts)
						except NFLogError as err:
							if err.errno not in ts_err_mask: raise
							result.append(None)
						else: result.append(ts.contents.tv_sec + ts.contents.tv_usec * 1e-6)
					else: raise NotImplementedError('Unknown nflog attribute: {}'.format(attr))
			_cb_result.append(result)
		except:
			_cb_result.append(StopIteration) # breaks the generator
			raise

	nflog_cb_t = ctypes.CFUNCTYPE(
		ctypes.c_void_p, *[ctypes.POINTER(ctypes.c_void_p)]*3 )
	c_cb = nflog_cb_t(callback)

	for qid in (qids if not isinstance(qids, int) else [qids]):
		qh = libnflog.nflog_bind_group(handle, qid)
		libnflog.nflog_set_mode(qh, 0x2, 0xffff) # NFULNL_COPY_PACKET
		if qthresh: libnflog.nflog_set_qthresh(qh, qthresh)
		if timeout: libnflog.nflog_set_timeout(qh, int(timeout * 100))
		if nlbufsiz: libnflog.nflog_set_nlbufsiz(qh, nlbufsiz)
		libnflog.nflog_callback_register(qh, c_cb)

	fd = libnflog.nflog_fd(handle)
	buff_len = nlbufsiz or 1*2**20 # not sure if size matters here
	buff = ctypes.create_string_buffer(buff_len)

	yield fd # yield fd for poll() on first iteration
	while True:
		_cb_result = list()
		try: pkt = libnflog.recv(fd, buff, buff_len, 0)
		except OSError as err:
			if err.errno == errno.ENOBUFS:
				log.warn( 'nlbufsiz seem'
					' to be insufficient to hold unprocessed packets,'
					' consider raising it via corresponding function keyword' )
				continue
			raise
		libnflog.nflog_handle_packet(handle, buff, pkt)
		for result in _cb_result:
			if result is StopIteration: raise result
			yield result


if __name__ == '__main__':
	src = nflog_generator([0, 1], extra_attrs=['len', 'ts'], nlbufsiz=2*2**20)
	fd = next(src)
	for pkt in src:
		if pkt is None: continue
		pkt, pkt_len, ts = pkt
		print('Got packet, len: {}, ts: {}'.format(pkt_len, ts))
		# print('Payload:', pkt.encode('hex'))
