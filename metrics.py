# -*- coding: utf-8 -*-
from __future__ import print_function

'Simple ad-hoc statsd client implementation'

import itertools as it, operator as op, functools as ft
import os, socket


def add_statsd_optz(parser):
	parser.add_argument('-m', '--statsd', metavar='host[:port]',
		help='host or host:port of statsd to send performance metrics to.')
	parser.add_argument('-n', '--statsd-metrics-prefix',
		metavar='prefix', default='{host}.nflog_pipe.',
		help='Prefix for metric names, passed to statsd (default: %(default)s).')
	parser.add_argument('-i', '--statsd-sampling',
		type=int, metavar='count', default=50,
		help='Statsd sampling rate (counter is being sent'
			' sampled every 1/Nth of the time, default: %(default)s).')
	parser.add_argument('-t', '--statsd-type', metavar='type', default='m',
		help='Statsd type suffix to use, as in "send \'some_metric:123|c\'", where \'c\''
			'  is the type in question (see statsd implementation docs for the'
			' list of supported types, default: %(default)s).')

def statsd_from_optz(optz):
	if optz.statsd:
		statsd_obj = optz.statsd.rsplit(':', 1)
		if len(statsd_obj) > 1: statsd_obj[1] = int(statsd_obj[1])
		statsd_obj = statsd( *statsd_obj,
			prefix=optz.statsd_metrics_prefix.format(host=os.uname()[1]),
			sampling=optz.statsd_sampling )
		next(statsd_obj)
		return statsd_obj
	else: return None


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
		sock.sendto('{}:{}|m'.format(name, val), dst)
		if val > val_max: val = 0
