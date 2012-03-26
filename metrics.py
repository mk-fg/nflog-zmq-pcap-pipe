# -*- coding: utf-8 -*-
from __future__ import print_function

'Simple ad-hoc statsd client implementation'

import itertools as it, operator as op, functools as ft
import socket

def statsd(host, port=8125, prefix=None, sampling=1, val_max=2**127):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	dst = host, port
	yield sock.fileno()
	vals = dict()
	while True:
		name = yield
		val = vals[name] = vals.get(name, 0) + 1
		if val % sampling != 0: continue
		if prefix: name = prefix + name
		sock.sendto('{}:{}|c'.format(name, val), dst)
		if val > val_max: val = 0
