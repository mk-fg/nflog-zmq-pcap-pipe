nflog-zmq-pcap-pipe
--------------------

Set of scripts to allow selective dumping of packets with netfilter NFLOG module
and sending of these over zeromq channel to remote host (producing pcap stream
there) for analysis.

Use-case is sending traffic to [Snort IDS](http://snort.org) on a remote machine
with some pre-filtering (with iptables, since it's generally faster, simplier
and more flexible) to exclude encrypted and irrelevant traffic (like raw
VPN/IPSec packets and p2p).

If nothing receives the flow on the other side (or has any kind of temporary
network problems), packets are buffered up to "--zmq-buffer" (ZMQ_HWM) count and
just dropped afterwards - overall goal is to make the channel as robust and
easy-to-maintain as possible, and [ZeroMQ](http://zeromq.org/) helps a lot here.

Multiple senders (possibly from multiple hosts) can be connected to one
receiver.

Packet counter metrics on both ends can be send to statsd (think
[etsy/statsd](https://github.com/etsy/statsd) or any of
[these](joemiller.me/2011/09/21/list-of-statsd-server-implementations)). Disabled
by default, see --statsd-* options.


Usage
--------------------

Simple example for sending outgoing traffic to some random IP address for
analysis from gateway.host to ids.host.

gateway.host:

	iptables -I OUTPUT -d google.com -j NFLOG --nflog-group 0 --nflog-range 65535
	ip6tables -I OUTPUT -d ipv6.google.com -j NFLOG --nflog-group 1 --nflog-range 65535
	nflog-zmq-send 0,1 tcp://ids.host:1234

ids.host:

	mkfifo /run/snort.pcap
	nflog-pcap-recv tcp://0.0.0.0:1234 /run/snort.pcap &
	snort --treat-drop-as-alert -r /run/snort.pcap

("--treat-drop-as-alert" option is useful because snort can't really "drop" or
otherwise control real traffic)

For syntax of ZeroMQ endpoints, see [zeromq
docs](http://api.zeromq.org/2-1:zmq-connect).

Throughput rate can be controlled either via "--rate-control" option (available
in nflog-zmq-send and nflog-pcap-recv) or by piping traffic through separate
binaries - nflog-zmq-compress and nflog-zmq-decompress.

Packets get squashed+compressed (zlib) upon reaching configurable "low
watermark" and dropped upon reaching "high watermark", otherwise sent out as
soon as possible.

Both "--rate-control" option and separate binaries use the same underlying code
(and have same CLI options), but the advantage is in offloading compression cpu
cost to a separate thread at the cost of associated ipc overhead.


Requirements
--------------------

* Python 2.7 with ctypes support and zlib if "--rate-control" or nflog-zmq-compressor is used
* [libnetfilter_log.so.1](http://netfilter.org/projects/libnetfilter_log) on the sending side
* [pyzmq](https://github.com/zeromq/pyzmq)


Advantages of nflog vs low-level traffic capture options (e.g. via libpcap)
--------------------

* Extensive filtering capabilities - you have all the netfilter modules and
techniques at your disposal, so non-interesting high-volume traffic - tor, p2p,
etc - can be skipped.
* Ability to capture tunneled packets after decryption (traffic coming from
ipsec, pptp, openvpn, ssh, etc) or transformation (stripping of ipip wrapping,
netlink re-injection, etc).
* Runtime reconfiguration.
* Superior performance.


Why ctypes (and not, say, [nflog-bindings](https://www.wzdftpd.net/redmine/projects/nflog-bindings))?
--------------------

* I'm more comfortable writing python than C or cython.
* nflog-bindings leaks RAM like titanic, uses printf() in the code (and for each.
  captured packet, no less), horribly incomplete and buggy (there is an
  nflog-bindings-based implementation in git-log).
* No extra deps, consistency.
* Better support in non-cPython.
