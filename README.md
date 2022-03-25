# pflogflowd(8) - OpenBSD packet filter log flow collector

pflogflowd aggregates the network packets logged with pf(4) via a
pflog(4) pseudo interface and records the resulting flows in a
Clickhouse database.

Flows are collected within timeslices, each of which is 4 seconds
long by default. Flow records contain the following protocol fields:

- IP version (IPv4 or IPv6)
- IP protocol (TCP, UDP, etc)
- Source and destination IP addresses
- Source and desitnation ports for TCP/UDP/UDPlite protocols
- ICMP type and code fields, and id for echo (ping) packets
- GRE flags and protocol fields, and Key for GRE v0 headers
- The number of packets and bytes counted in the timeslice

The collector augments the flow with the following metadata from
the network stack and packet filter:

- Beginning and ending timestamps for the timeslice
- The virtual network identifier from the underlying interface
- The direction the packet was travelling over the interface
- The action from the rule that caused the packet to be logged

## Todo

- Improve the robustness of the POSTs into clickhouse

