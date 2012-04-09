# -*- coding: utf-8 -*-
from __future__ import print_function

'Simple ad-hoc statsd client implementation'

import itertools as it, operator as op, functools as ft


def add_statsd_optz(parser):
	parser.add_argument('-m', '--statsd', metavar='host[:port]',
		help='host or host:port of statsd to send performance metrics to.'
			'Metrics are sent as increments since the last send.')
	parser.add_argument('-n', '--statsd-metrics-prefix',
		metavar='prefix', default='{host}.nflog_pipe.',
		help='Prefix for metric names, passed to statsd (default: %(default)s).')
	parser.add_argument('-i', '--statsd-sampling',
		metavar='count[/interval]', default='50/60',
		help='Statsd sampling rate. Chance the counter is being sent is'
			' calculated as (samples / count)[ * ((time_last_sent - time) / interval)]'
			'(default: %(default)s).')
	parser.add_argument('-t', '--statsd-type', metavar='type', default='m',
		help='Statsd type suffix to use, as in "send \'some_metric:123|c\'", where \'c\''
			'  is the type in question (see statsd implementation docs for the'
			' list of supported types, default: %(default)s).')

def statsd_from_optz(optz):
	if optz.statsd:
		import os
		statsd_obj = optz.statsd.rsplit(':', 1)
		if len(statsd_obj) > 1: statsd_obj[1] = int(statsd_obj[1])
		try:
			sampling = map(float, optz.statsd_sampling.split('/'))
			try: sampling, interval = sampling
			except TypeError: interval = None
		except:
			parser.error('Invalid value for --statsd-sampling: {}'.format(optz.statsd_sampling))
		statsd_obj = statsd( *statsd_obj,
			prefix=optz.statsd_metrics_prefix.format(host=os.uname()[1]),
			sampling=sampling, interval=interval, mtype=optz.statsd_type )
		next(statsd_obj)
		return statsd_obj
	else: return None


def statsd( host, port=8125, prefix=None,
		sampling=None, interval=None, threshold=None, mtype='m' ):
	import socket
	from random import random
	from time import time

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	dst = host, port
	yield sock.fileno()
	vals = dict()
	ts_send, ts_sampling, ts_chance =\
		time(), 1.0, max(int(sampling / 2), 1)

	while True:
		name = yield
		val = vals.get(name, 0)
		if sampling and interval and val % ts_sampling == 0:
			ts_chance = (time() - ts_send) / interval
		val = vals[name] = val + 1
		if not sampling or ts_chance * (val / sampling) > random():
			if prefix: name = prefix + name
			sock.sendto('{}:{}|{}'.format(name, val, mtype), dst)
			val = 0
			if interval: ts_send = time()
