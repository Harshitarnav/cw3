## Part 1: Simple L4 firewall in OpenFlow. (50%)

Suppose you are a network administrator in a small office.
You want to prevent TCP connections from being initiated by external hosts, while allowing
for those initiated by the internal hosts. Fortunately you
have deployed an OpenFlow switch to which all the internal hosts connect.  Being
inspired by this scenario, implement an OpenFlow controller to achieve this
feature. You use [Ryu](https://ryu-sdn.org/) to implement an OpenFlow controller in
Python and [Mininet](http://mininet.org/) to emulate a network.

**Specification:**
The emulated network consists of one internal host, one external host and one switch.
The switch has two ports; port 1 and port 2 connect to the internal and external host, respectively.
Your controller
must insert the flow to the switch when observing a TCP-over-IPv4 packet that arrives
at the switch port 1.
Further, when the controller sees a returning packet in this TCP connection
arriving at switch port 2, it must forward this packet to switch port 1 and insert the
corresponding flow to the switch.
These flows must match against input switch port, network layer protocol, source IP address,
destination IP address, transport layer protocol, source port and destination port.
  All the packets that are *not* TCP-over-IPv4 can pass the switch or controller (i.e., forwarded from switch port 1 to 2 and vice versa). You do not have to insert a flow for non-TCP-over-IPv4 packets.
Further, when the controller receives TCP packets arriving at switch port 1 but with illegal combination of TCP flags, which are 1.) both SYN and FIN set, 2.) both SYN and RST set or 3.) no flags are set, it must not forward 
those packets nor create the flow in the switch.
Implement these features by completing `_packet_in_handler()` method in [`l4state.py`](./l4state.py).
Do not remove any existing lines, and do not import any other modules. Also, do not define new class nor methods.

You can test the program in Mininet:
```
vagrant@ubuntu-focal:~$ ryu-manager l4state.py
```
and in another window (the output of `h1 iperf -c h2 -t 2` is based on correctly-implemented [l4state.py](./l4state.py)):
```
vagrant@ubuntu-focal:~$ sudo mn --topo single,2 --mac --controller remote --switch ovsk
*** Creating network
*** Adding controller
Connecting to remote controller at 127.0.0.1:6653
*** Adding hosts:
h1 h2 
*** Adding switches:
s1 
*** Adding links:
(h1, s1) (h2, s1) 
*** Configuring hosts
h1 h2 
*** Starting controller
c0 
*** Starting 1 switches
s1 ...
*** Starting CLI:
mininet> h2 iperf -s &
mininet> h1 iperf -c h2 -t 2
------------------------------------------------------------
Client connecting to 10.0.0.2, TCP port 5001
TCP window size: 85.3 KByte (default)
------------------------------------------------------------
[  3] local 10.0.0.1 port 40252 connected with 10.0.0.2 port 5001
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0- 2.1 sec  10.4 MBytes  42.3 Mbits/sec
mininet> 
```
`h2 iperf -s &` starts an iperf server at h2 connected to the switch port 2.
`h1 iperf -c h2 -t 2` initiates a TCP connection to that iperf server and
generates traffic for 2 second.

### Marking Criteria

1. [l4state.py](./l4state.py) can pass non-TCP-over-IPv4 packets that are sent from host
2 to host 1 and block TCP-over-IPv4 packets that are sent from host 2 to host 1 before seeing any packets sent from host 1 to host 2, which must pass the following test (**20%**):
```
python3 -m pytest tests/test_l4state.py::test_l4state1
```
2. [l4state.py](./l4state.py) can insert the correct flows in the switch, which must pass the following test (**20%**):
```
python3 -m pytest tests/test_l4state.py::test_l4state2
```
3. [l4state.py](./l4state.py) meet all the requirements in the **Specification** paragraph above, which must pass the following test (**10%**):
```
python3 -m pytest tests/test_l4state.py
```
Note that 1 and 2 are intermediate steps to meet the next criteria, the possible score is 0%, 4%, 8% or 10%.

### Hints

In the `_packet_in_handler`, you will first need to define the controller action for non-TCP-over-IPv4 packets, which just forwards packets between switch port 1 and 2.
You can test this behavior in the above Mininet environment by `h1 ping -c 1 h2`
and `h2 ping -c 1 h1` (ping generates ICMP packets i.e., non-TCP-over-IPv4) being successful instead of the `iperf` commands (iperf generates TCP traffic).
In addition to deciding the output port, you will need to create the action
(`acts` passed to `OFPPacketOut()`, see [l2learn.py](./l2learn.py) for the syntax).
As described in the specification, you do not have to insert a flow to the
switch for non-TCP-over-IPv4 packets.

You will then implement *exceptional* cases for TCP-over-IPv4 packets.
You will first need to identify such a packet, and extract the flow key that is a tuple of `(<srcip>, <dstip>, <srcport>, <dstport>)`.

Then, if the packet comes from port 1, search for the hash table private in the controller, which is `ht`, a `set()` object initiated in `__init__()` method of the `L4State14` class (this is NOT the flow table in the switch); insert the flow key in `ht` if it does not exist. This hash table is used to identify, when the controller receives a TCP-over-IPv4 packet that arrives at switch port 2, whether the corresponding flow has been initiated by the internal host or not.
Then also insert the flow in the switch, so that the controller does not have to process the packets in this TCP connection that arrive at switch port 1.

If the packet comes from port 2 and the corresponding flow entry in `ht`, which
is the four-tuple of the packet with source and destination addresses and ports swapped (remember how the entry has been created based on the packet arriving at port 1), does not exist, it should be dropped, otherwise it should be forwarded to switch port 1 **and** the flow entry is inserted in the switch, again so that the controller does not have to process packets in the same flow (port 2 to 1).
The sample solution (not provided) consists of 75 lines, but this number is just
a reference, and no need to match.


## Part 2: L4 Load Balancing in OpenFlow (50%)

Suppose you operate two servers and want to distribute passive TCP connections to those servers based on layer 4 load balancing.
An OpenFlow switch mediates all the traffic to those servers.

**Specification:** Your task is to implement this logic by completing `_packet_in_handler()` method in [`l4lb.py`](./l4lb.py), using Ryu and Mininet again. The client and two servers have IP addresses of 10.0.0.1/24, 10.0.0.2/24 and 10.0.0.3/24 in the same broadcast domain, and connects to port 1, 2 and 3, respectively.
The client attempts to initiate TCP connections to the virtual IP address (VIP) 10.0.0.10 (supposed to be advertised by DNS, although we do not install a DNS server in this experiment network), and the OpenFlow switch (or controller for first matching packets) transforms the destination IP address of the ingress (client to VIP) TCP packets to one of the server IP addresses, and source IP address of the egress (one of the servers to client) TCP packets to the VIP.
The first TCP connection should be redirected to server 1 (10.0.0.2), the
second one should be redirected to server 2 (10.0.0.3), third one to server 1, and so on.
To meet criteria 1 and 2 described in Marking Criteria below , we can configure the client's ARP table to associate the VIP with the MAC address of server 1 (00:00:00:00:00:02) (see the output of `ip neigh` commands in mininet below). Therefore, when the packets are redirected to server 2 (00:00:00:00:00:03), their destination MAC address also needs to be transformed, otherwise those packets are discarded at the server's network interface.
To meet the third criteria, the controller must respond to ARP requests issued
by the client or servers, using the same mapping of IP addresses and MAC
addresses as the static ARP configuration case.
Your OpenFlow controller must work as follows.
The controller inserts a flow with packet transformation action(s) to the switch when it sees a TCP/IPv4 packet sent by the client.
It also must insert a flow with appropriate action(s) when it sees a TCP/IPv4
sent by one of the servers.
You do not have to consider timeout of the flows in the switch or flow entries in the controller.
Do not remove any existing lines, and do not import any other modules.

For testing, the controller (i.e., `l4lb.py`) and Mininet will be instantiated as follows (the output from the `h2 iperf -c h1 -t 1` and `h3 pkill iperf` is based on the correctly implemented version of [l4lb.py](./l4lb.py)):
```
vagrant@ubuntu-focal:~$ ryu-manager l4lb.py
```
In another window:
```
vagrant@ubuntu-focal:~$ sudo mn --topo single,3 --mac --controller remote --switch ovsk
*** Creating network
*** Adding controller
Connecting to remote controller at 127.0.0.1:6653
*** Adding hosts:
h1 h2 h3 
*** Adding switches:
s1 
*** Adding links:
(h1, s1) (h2, s1) (h3, s1) 
*** Configuring hosts
h1 h2 h3 
*** Starting controller
c0 
*** Starting 1 switches
s1 ...
*** Starting CLI:
mininet> h1 ip neigh add 10.0.0.10 lladdr 00:00:00:00:00:02 dev h1-eth0 nud permanent
mininet> h2 ip neigh add 10.0.0.1 lladdr 00:00:00:00:00:01 dev h2-eth0 nud permanent
mininet> h3 ip neigh add 10.0.0.1 lladdr 00:00:00:00:00:01 dev h3-eth0 nud permanent
mininet>
mininet> h2 iperf -s &
mininet> h3 iperf -s &
mininet> h1 iperf -c 10.0.0.10 -t 1
------------------------------------------------------------
Client connecting to 10.0.0.10, TCP port 5001
TCP window size: 12.7 MByte (default)
------------------------------------------------------------
[  3] local 10.0.0.1 port 36014 connected with 10.0.0.10 port 5001
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0- 1.0 sec  5.50 GBytes  47.2 Gbits/sec
mininet> h1 iperf -c 10.0.0.10 -t 1
------------------------------------------------------------
Client connecting to 10.0.0.10, TCP port 5001
TCP window size: 1.95 MByte (default)
------------------------------------------------------------
[  3] local 10.0.0.1 port 39598 connected with 10.0.0.10 port 5001
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0- 1.0 sec  5.62 GBytes  48.3 Gbits/sec
mininet> h2 pkill iperf
------------------------------------------------------------
Server listening on TCP port 5001
TCP window size: 85.3 KByte (default)
------------------------------------------------------------
[  4] local 10.0.0.2 port 5001 connected with 10.0.0.1 port 36014
[ ID] Interval       Transfer     Bandwidth
[  4]  0.0- 1.0 sec  5.50 GBytes  45.9 Gbits/sec
mininet> h3 pkill iperf
------------------------------------------------------------
Server listening on TCP port 5001
TCP window size: 85.3 KByte (default)
------------------------------------------------------------
[  4] local 10.0.0.3 port 5001 connected with 10.0.0.1 port 39598
[ ID] Interval       Transfer     Bandwidth
[  4]  0.0- 1.0 sec  5.62 GBytes  47.9 Gbits/sec
```
Note: `ip neigh` commands configure the ARP table statically for relevant hosts.

### Marking Criteria

1. [l4lb.py](./l4lb.py) can mediate three way handshake between the client and server 1 for the first connection, which must pass the following test (**20%**):
```
python3 -m pytest tests/test_l4lb.py::test_l4lb1
```

2. [l4lb.py](./l4lb.py) can mediate three way handshake between the client and server 2 for the second connection, and between the client and server 1 for the third connection, which must pass the following test (**20%**):
```
python3 -m pytest tests/test_l4lb.py::test_l4lb2
```

3. [l4lb.py](./l4lb.py) can respond to ARP requests issued by the client or servers that do not statically configure their ARP table (i.e., no `ip neigh` commands when starting mininet), which must pass the following test (**10%**):
```
python3 -m pytest tests/test_l4lb.py
```
Note that 1 and 2 are intermediate steps to meet the next criteria, the possible score is 0%, 4%, 8% or 10%.

The sample solution (not provided) consists of 136 lines, but this number is just
a reference, and no need to match.

### Hints

To send an ARP REPLY packet, you can use the `_send_packet()` method in
[l4lb.py](./l4lb.py). For packet manipulation reference, the [official Ryu document](https://ryu.readthedocs.io/en/latest/index.html) should be useful.
