pcap-zmq-pipe: Tool to send pcap stream/dump over network (0mq) for real-time (or close to) analysis
--------------------

Simple script to allow selective dumping of packets with iptables/ulogd2 or
BPF/tcpdump and sending of these over zeromq channel to remote host for
analysis.

Aside from filtering (which is outside of scope of the app), throughput rate is
checked. Packets get squashed+compressed (zlib) upon reaching "low watermark"
and dropped upon reaching "high watermark", otherwise sent out as soon as
possible.

Use-case is sending traffic to [SNORT IDS](http://snort.org) on a remote machine
with some pre-filtering (with iptables, since it's generally faster, simplier
and more flexible) to exclude encrypted and irrelevant traffic (like raw
VPN/IPSec packets and p2p).

Running IDS on the same machine is not an option (machine too slow) and piping
all the traffic to a dedicated IDS machine is generally undesirable due to added
latency, setup complexity and availability issues.

pcap dump in my case is generated via NFLOG netfilter target and [ulogd
2.x](http://www.netfilter.org/projects/ulogd/) userspace daemon.


Usage
--------------------

gateway.host (with ulogd configured to use pcap output plugin):

	mkfifo /var/log/ulogd.pcap
	./pcap-zmq-send.py /var/log/ulogd.pcap tcp://ids.host:1234 &
	ulogd

ids.host:

	mkfifo /var/log/ulogd.pcap
	./pcap-zmq-recv.py tcp://ids.host:1234 /var/log/ulogd.pcap &
	snort --treat-drop-as-alert -r /var/log/ulogd.pcap

("--treat-drop-as-alert" option is useful because snort can't really "drop" or
otherwise control real traffic)
