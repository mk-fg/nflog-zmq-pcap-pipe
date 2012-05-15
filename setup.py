#!/usr/bin/env python

from setuptools import setup, find_packages
import os

pkg_root = os.path.dirname(__file__)

setup(

	name = 'nflog-zmq-pcap-pipe',
	version = '12.05.4',
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = 'nflog pcap zeromq traffic analysis ids',
	url = 'http://github.com/mk-fg/graphite-metrics',

	description = 'Tool to collect nflog and pipe it to a pcap stream/file'
		' over network (0mq) for real-time (or close to that) analysis',
	long_description = open(os.path.join(pkg_root, 'README.md')).read(),

	classifiers = [
		'Development Status :: 4 - Beta',
		'Environment :: No Input/Output (Daemon)',
		'Intended Audience :: Developers',
		'Intended Audience :: System Administrators',
		'Intended Audience :: Telecommunications Industry',
		'License :: OSI Approved',
		'Operating System :: POSIX :: Linux',
		'Programming Language :: Python',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 2 :: Only',
		'Programming Language :: Python :: Implementation :: CPython',
		'Topic :: Internet',
		'Topic :: Security',
		'Topic :: System :: Networking :: Monitoring',
		'Topic :: System :: Operating System Kernels :: Linux' ],

	install_requires = ['pyzmq'],

	packages = find_packages(),

	entry_points = {
		'console_scripts': [
			'{} = nflog_zmq_pcap_pipe.{}:main'.format(name, name.replace('-', '_'))
			for name in [ 'nflog-zmq-send', 'nflog-zmq-compress',
				'nflog-zmq-decompress', 'nflog-pcap-recv', 'nflog-pcap-query' ] ] } )
