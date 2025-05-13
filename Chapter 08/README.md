# Chapter 8 - eBPF networking

## Examples

1. `BPF_PROG_TYPE_SOCKET_FILTER` - Demonstration of a eBPF packet filter using a hard-coded BPF program `ip and tcp`
2. `BPF_PROG_TYPE_SCHED_CLS` - Demonstration of a `tc` packet classifier.
3. `BPF_PROG_TYPE_SCHED_ACT` - Demonstration of a `tc` packet action. This program drops 7% of ICMP traffic.
4. `BPF_PROG_TYPE_XDP` - Demonstration of three programs; `drop_packets` which drops all IP/ICMP packets, `icmp_server` which intercepts ICMP ping packets before they reach the Linux stack and returns a response, `load_balancer` (coming soon) which acts as a very basic TCP load balancer for traffic destined for port 8080.
5. `BPF_PROG_TYPE_CGROUP_SOCK` - Demonstrates running a program on v4 socket create within the cgroup that blocks any PF_INET && SOCK_RAW && IPPROTO_ICMP sockets
6. `BPF_PROG_TYPE_LWT_IN` - Demonstrates a BPF program attached to a tunnel that counts the number of packets per protocol (IP only).
7. `BPF_PROG_TYPE_LWT_SEG6LOCAL` - Demonstration of a segment routing BPF program that adds a segment routing header for packets parsing through the tunnel.
8. `BPF_PROG_TYPE_SOCK_OPS` - Demonstration of a BPF program that modifies send and recieve socket buffer sizes.
9. `BPF_PROG_TYPE_SK_MSG` - Demonstration of dropping messages (via `sendmsg()`) as well as redirecting them to a specific socket if it matches a specific criteria.
10. `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` - Demonstration of a BPF program that's attached to cgroup that disslows IPv6/ UDP/ RAW sockets.
11. `BPF_PROG_TYPE_CGROUP_SOCKOPT` - Demonstration of a BPF program attached to a cgroup that controls what `setsockopt` options can be applied.
12. `BPF_PROG_TYPE_SK_LOOKUP` - Demonstration of a BPF program that listens to multiple ports and redirects traffic back to a single process.
13. `BPF_PROG_TYPE_NETFILTER` - Demonstration of an eBPF program being attached to a `netfilter` hook.
14. `BPF_PROG_TYPE_SK_REUSEPORT` - Demonstration of a basic server listening on multiple IP addresses.
15. `BPF_PROG_TYPE_SK_SKB` - Demonstration of a BPF program that bypasses the networking stack to send traffic and uses sockmap instead.
16. `BPF_PROG_TYPE_FLOW_DISSECTOR` - Demonstration of a custom flow-dissector that is mocked out to perform dissection on IP/OSPF packets.