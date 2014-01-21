nflog-zmq-pcap-pipe
--------------------

Set of scripts to allow selective dumping of packets with netfilter NFLOG module
and sending of these over zeromq channel to remote host (producing pcap stream
there) for analysis.

Use-case is sending traffic to [Snort IDS](http://snort.org) on a remote machine
with some pre-filtering (with iptables, since it's generally faster, simplier
and more flexible than BPF or userspace filters) to exclude encrypted and
irrelevant traffic (like raw VPN/IPSec packets and p2p).


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
otherwise control real traffic in this scenario)

##### ZeroMQ endpoints

All the source/destination sockets are [ZeroMQ](http://zeromq.org/) endpoints.
For syntax of these, see [zeromq docs](http://api.zeromq.org/2-2:zmq-connect).

If nothing receives the flow on the other side of the pipe (or has any kind of
temporary network problems), packets are buffered up to "--zmq-buffer"
(ZMQ_SNDHWM) count and just dropped afterwards - overall goal is to make the
channel as robust and easy-to-maintain as possible, and zeromq helps a lot here.

Multiple senders (possibly from multiple hosts) can be connected to one
receiver.

##### Rate control

Throughput rate can be controlled either via "--rate-control" option (available
in nflog-zmq-send and nflog-pcap-recv) or by piping traffic through separate
binaries - nflog-zmq-compress and nflog-zmq-decompress.

Packets get squashed+compressed (zlib) upon reaching configurable "low
watermark" ("--lwm" option) and dropped upon reaching "high watermark" ("--hwm"
option), otherwise sent out as soon as possible.

Both "--rate-control" option and separate binaries use the same underlying code
(and have same CLI options), but the advantage is in offloading compression cpu
cost to a separate thread at the cost of associated ipc overhead.

Note that nflog-pcap-recv do *not* have any detection of whether received data
is compressed, so if "--rate-control" is enabled on the sending side (or
nflog-zmq-compress is used), same flag (or nflog-zmq-decompress) *has to be
used* on (or setup before) the receiver, otherwise traffic in the resulting dump
will be corrupted (i.e. packets batched together and fully compressed).

##### libnetfilter_log controls

nflog-zmq-send binary has the options to control parameters of netlink socket
which it creates.

See [libnetfilter_log
documentation](http://www.netfilter.org/projects/libnetfilter_log/doxygen/group__Log.html)
for more verbose description of these.

##### nflog-pcap-recv buffer interface

Flag "--buffer-interface" enables the receiver to keep up to "--buffer-window"
MiB of last traffic, without delaying pcap throughput though.

Contents of this buffer can be easily retreived (in pcap format) for later
inspection via nflog-pcap-query binary (or by sending any request to specified
socket from anywhere).

Idea is to have much more complete picture of what's happening on the wire at
the moment of some event, not just the single packet or flow which was matched.
Generated pcap dump can be inspected by generic tools like wireshark or tcpdump.

##### Metrics (statsd interface)

Packet counter metrics on both ends can be send to statsd (think
[etsy/statsd](https://github.com/etsy/statsd) or any of
[these](joemiller.me/2011/09/21/list-of-statsd-server-implementations)). Disabled
by default, see --statsd-* options.

Probably a bit broken at the moment, fixes are welcome.


Requirements
--------------------

* Python 2.7 with ctypes support and zlib if "--rate-control" or nflog-zmq-compressor is used
* [libnetfilter_log.so.1](http://netfilter.org/projects/libnetfilter_log) on the sending side
* [pyzmq](https://github.com/zeromq/pyzmq) and [zeromq](http://zeromq.org/),
  version 2.2.0 or higher.

Note that pyzmq detects zeromq version at build-time, so even though it will
work after non-major zeromq lib updates (like 2.1.X -> 2.2.X), it won't have
support for any of the new features and has to be rebuilt.


Advantages of nflog vs low-level traffic capture options (e.g. via libpcap)
--------------------

* Extensive filtering capabilities - you have all the netfilter modules and
  techniques at your disposal, so non-interesting high-volume traffic - tor,
  p2p, etc - can be skipped.
* Ability to capture tunneled packets after decryption (traffic coming from
  ipsec, pptp, openvpn, ssh, etc) or transformation (stripping of ipip wrapping,
  netlink re-injection, etc).
* Runtime reconfiguration (via iptables, for example).
* Superior performance.


Why ctypes (and not, say, [nflog-bindings](https://www.wzdftpd.net/redmine/projects/nflog-bindings))?
--------------------

* I'm more comfortable writing python than C or cython.
* nflog-bindings leaks RAM like titanic, uses printf() in the code (and for each.
  captured packet, no less), horribly incomplete and buggy (there is an
  nflog-bindings-based implementation in git-log).
* No extra deps, consistency.
* Better support in non-cPython.

There's a very similar bindings module in
[scapy-nflog-capture](https://github.com/mk-fg/scapy-nflog-capture), based on
cffi instead of ctypes that should be much more segfault-free and future-proof
than the one used here.
If you experience any issues with the current module (like segfault right on
start), try swapping nflog.py for that one.
