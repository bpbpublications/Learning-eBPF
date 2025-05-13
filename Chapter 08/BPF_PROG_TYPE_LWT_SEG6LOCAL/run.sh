#!/bin/bash

BPF_FILE="seg6.bpf.o"
readonly NS1="ns1-$(mktemp -u XXXXXX)"
readonly NS2="ns2-$(mktemp -u XXXXXX)"
readonly NS3="ns3-$(mktemp -u XXXXXX)"

msg="skip all tests:"
if [ $UID != 0 ]; then
    echo $msg please run this as root >&2
    exit $ksft_skip
fi

TMP_FILE="/tmp/selftest_lwt_seg6local.txt"

cleanup()
{
    if [ "$?" = "0" ]; then
        echo "selftests: test_lwt_seg6local [PASS]";
    else
        echo "selftests: test_lwt_seg6local [FAILED]";
    fi

    set +e
    ip netns del ${NS1} 2> /dev/null
    ip netns del ${NS2} 2> /dev/null
    ip netns del ${NS3} 2> /dev/null
    # rm -f $TMP_FILE
}

set -e
cleanup

ip netns add ${NS1}
ip netns add ${NS2}
ip netns add ${NS3}

trap cleanup 0 2 3 6 9

ip link add veth1 type veth peer name veth2
ip link add veth3 type veth peer name veth4

ip link set veth1 netns ${NS1}
ip link set veth2 netns ${NS2}
ip link set veth3 netns ${NS2}
ip link set veth4 netns ${NS3}

ip netns exec ${NS1} ip link set dev veth1 up
ip netns exec ${NS2} ip link set dev veth2 up
ip netns exec ${NS2} ip link set dev veth3 up
ip netns exec ${NS3} ip link set dev veth4 up
ip netns exec ${NS3} ip link set dev lo up

ip netns exec ${NS1} ip -6 addr add fb00::12/16 dev veth1 scope link
ip netns exec ${NS1} ip -6 route add fb00::21 dev veth1 scope link
ip netns exec ${NS2} ip -6 addr add fb00::21/16 dev veth2 scope link
ip netns exec ${NS2} ip -6 addr add fb00::34/16 dev veth3 scope link
ip netns exec ${NS2} ip -6 route add fb00::43 dev veth3 scope link
ip netns exec ${NS3} ip -6 addr add fb00::43/16 dev veth4 scope link

ip netns exec ${NS1} ip -6 addr add fb00::1/16 dev lo
ip netns exec ${NS1} ip -6 route add fb00::6 dev veth1 via fb00::21

ip netns exec ${NS2} ip -6 route add fb00::6 encap bpf in obj ${BPF_FILE} sec lwt_seg6local dev veth2
ip netns exec ${NS2} ip -6 route add fd00::1 dev veth3 via fb00::43 scope link

ip netns exec ${NS3} ip -6 addr add fb00::6/16 dev lo
ip netns exec ${NS3} ip -6 addr add fd00::1/16 dev lo

ip netns exec ${NS1} sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec ${NS2} sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec ${NS3} sysctl net.ipv6.conf.all.forwarding=1 > /dev/null

ip netns exec ${NS3} sysctl net.ipv6.conf.all.seg6_enabled=1 > /dev/null
ip netns exec ${NS3} sysctl net.ipv6.conf.lo.seg6_enabled=1 > /dev/null
ip netns exec ${NS3} sysctl net.ipv6.conf.veth4.seg6_enabled=1 > /dev/null

ip netns exec ${NS3} nc -l -6 -u -d 8888 > $TMP_FILE &
ip netns exec ${NS1} bash -c "echo 'hello' | nc -w0 -6 -u -p 2121 -s fb00::1 fb00::6 8888"
sleep 5
kill -TERM $!

if [[ $(< $TMP_FILE) != "foobar" ]]; then
    exit 1
fi

exit 0