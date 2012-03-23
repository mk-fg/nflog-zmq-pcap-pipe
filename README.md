pcap-zmq-pipe: tool to send pcap stream/dump over network (0mq) for real-time (or close to) analysis
--------------------

Set of scripts to allow selective dumping of packets with netfilter NFLOG module
and sending of these over zeromq channel to remote host for analysis.

Aside from filtering (which is outside of scope of the app), throughput rate is
checked. Packets get squashed+compressed (zlib) upon reaching "low watermark"
and dropped upon reaching "high watermark", otherwise sent out as soon as
possible.

Use-case is sending traffic to [SNORT IDS](http://snort.org) on a remote machine
with some pre-filtering (with iptables, since it's generally faster, simplier
and more flexible) to exclude encrypted and irrelevant traffic (like raw
VPN/IPSec packets and p2p).

If nothing receives the flow on the other side (or has any kind of temporary
network problems), packets are buffered up to "--zmq-buffer" (ZMQ_HWM) count and
just dropped afterwards - overall goal is to make the channel as robust and
easy-to-maintain as possible, and [ZeroMQ](http://zeromq.org/) helps a lot here.

Multiple senders (possibly from multiple hosts) can be connected to one
receiver.

Python implementation performance is not stellar, but borderline-acceptable.


Usage
--------------------

gateway.host (with ulogd configured to use pcap output plugin):

	iptables -A OUTPUT --destination 1.2.3.4 -j NFLOG --nflog-group 0
	iptables -A OUTPUT --destination 1.2.3.5 -j NFLOG --nflog-group 1
	./pcap-zmq-send.py 0,1 tcp://ids.host:1234

ids.host:

	mkfifo /run/snort.pcap
	./pcap-zmq-recv.py tcp://ids.host:1234 /run/snort.pcap &
	snort --treat-drop-as-alert -r /run/snort.pcap

("--treat-drop-as-alert" option is useful because snort can't really "drop" or
otherwise control real traffic)


Requirements
--------------------

* Python 2.7 with ctypes support, and zlib if "low watermark" is enabled
* [libnetfilter_log](http://netfilter.org/projects/libnetfilter_log) on the sending side
* [nflog-bindings](https://www.wzdftpd.net/redmine/projects/nflog-bindings) on the sending side
* [libpcap.so.1](http://www.tcpdump.org/) on the receiving side
* [pyzmq](https://github.com/zeromq/pyzmq)
