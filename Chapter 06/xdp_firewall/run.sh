#!/bin/bash

NETNS_NAME="xdp-firewall-test"
n='sudo ip netns'
nexec="sudo ip netns exec $NETNS_NAME"

function setup_netns() {
    # add 'netns-1' network namespace where we'll
    # run our test.
    $n add $NETNS_NAME

    # setup loopback address
    $nexec ip addr add 127.0.0.1 dev lo

    # setup a dummy interface which can route to the default gw, and
    # setup a route to the default gw.
    $nexec ip link add name eth0 type dummy
    $nexec ip link set up eth0
    $nexec ip addr add 192.168.1.10/24 dev eth0
    $nexec ip route add default via 192.168.1.11

    # since 192.168.1.11 doesn't actually exist, create a perm arp-table entry
    # for it, allowing fib lookup to succeed.
    $nexec ip neigh add 192.168.1.11 dev eth0 lladdr "0F:0F:0F:0F:0F:0F" nud permanent
}

function teardown_netns() {
    $n del $NETNS_NAME
}

setup_netns
$nexec ./test
teardown_netns