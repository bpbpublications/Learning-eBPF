#!/usr/bin/env bash

if [[ $(id -u) -ne 0 ]]; then
    echo "Require root privilege"
    exit 1
fi

current_script=$(realpath $0)
current_dir=$(dirname $current_script)

echo_run () {
    echo "$@"
    $@ || exit 1
}

echo_ip_links(){
    array_test=()
    for iface in $(ip l | awk -F ":" '/^[0-9]+:/{dev=$2 ; if ( dev !~ /^ lo$/) {print $2}}')
    do
        printf "$iface\n"
        array_test+=("$iface")
    done
    echo ${array_test[@]}
}

enable_routing() {
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.default.rp_filter=0
    sysctl -w net.ipv4.conf.all.rp_filter=0
    for iface in $(echo_ip_links)
    do
        attr=(${iface//@/ })
        iface_name=${attr[0]}
        echo $iface_name
        sysctl -w net.ipv4.conf.$iface_name.rp_filter=0
    done
}

create_net() {
    ip netns add h1
    ip netns add r1
    ip netns add h2
    ip link add name h1_r1 type veth peer name r1_h1
    ip link add name r1_h2 type veth peer name h2_r1
    ip link set h1_r1 netns h1
    ip link set r1_h1 netns r1
    ip link set r1_h2 netns r1
    ip link set h2_r1 netns h2
    ip netns exec h1 ip link set h1_r1 up
    ip netns exec r1 ip link set r1_h1 up
    ip netns exec r1 ip link set r1_h2 up
    ip netns exec h2 ip link set h2_r1 up
    ip netns exec h1 ip link set lo up
    ip netns exec r1 ip link set lo up
    ip netns exec h2 ip link set lo up
    ip netns exec h1 ip addr add 192.168.10.2/24 dev h1_r1
    ip netns exec r1 ip addr add 192.168.10.1/24 dev r1_h1
    ip netns exec r1 ip addr add 192.168.20.1/24 dev r1_h2
    ip netns exec h2 ip addr add 192.168.20.2/24 dev h2_r1
    ip netns exec h1 ip route add default dev h1_r1 via 192.168.10.1
    ip netns exec h2 ip route add default dev h2_r1 via 192.168.20.1

    # h1
    ip netns exec h1 sysctl -w net.ipv4.ip_forward=1
    ip netns exec h1 sysctl -w net.ipv4.conf.default.rp_filter=0
    ip netns exec h1 sysctl -w net.ipv4.conf.all.rp_filter=0
    ip netns exec h1 sysctl -w net.ipv4.conf.h1_r1.rp_filter=0

    # r1
    ip netns exec r1 sysctl -w net.ipv4.ip_forward=1
    ip netns exec r1 sysctl -w net.ipv4.conf.default.rp_filter=0
    ip netns exec r1 sysctl -w net.ipv4.conf.all.rp_filter=0
    ip netns exec r1 sysctl -w net.ipv4.conf.r1_h1.rp_filter=0
    ip netns exec r1 sysctl -w net.ipv4.conf.r1_h2.rp_filter=0

    # h2
    ip netns exec h2 sysctl -w net.ipv4.ip_forward=1
    ip netns exec h2 sysctl -w net.ipv4.conf.default.rp_filter=0
    ip netns exec h2 sysctl -w net.ipv4.conf.all.rp_filter=0
    ip netns exec h2 sysctl -w net.ipv4.conf.h2_r1.rp_filter=0

}

test_net() {
    echo_run ip netns exec h1 ping -c 5 192.168.20.2
}

destroy_net() {
    echo_run ip netns delete h1
    echo_run ip netns delete r1
    echo_run ip netns delete h2
}

while getopts "cdt" opt; do
    case "${opt}" in
        d)
            destroy_net
            ;;
        c)
            create_net
            ;;
        t)
            test_net
            ;;
        *)
            exit 1
            ;;
    esac
done

# destroy_net
create_net
sleep 2
echo "Attaching BPF program to route...."
sudo ip netns exec r1 ip route add 192.168.20.2/32 encap bpf in obj lwt_in.bpf.o sec lwt_in dev r1_h2
sleep 2
test_net

MAP_ID=$(sudo ip netns exec r1 bpftool map list | grep "protocol_counts" | awk '{print $1}' | cut -f 1 -d :)

# Dump the map and parse its output
sudo ip netns exec r1 bpftool map dump id "$MAP_ID" | while read -r line; do
  # Extract key and value, ensuring proper parsing
  key=$(echo "$line" | grep -oP '(?<=key: )[0-9a-fA-F]+')
  value=$(echo "$line" | grep -oP '(?<=value: )[0-9a-fA-F]+')

  # Ensure key and value are not empty; default to 0 if missing
  key=${key:-0}
  value=${value:-0}

  # Convert key and value from hex to decimal (only if they are valid hex numbers)
  if [[ "$key" =~ ^[0-9a-fA-F]+$ ]]; then
    key=$((16#$key))
  fi
  if [[ "$value" =~ ^[0-9a-fA-F]+$ ]]; then
    value=$((16#$value))
  fi

  # Map protocol numbers to human-readable names
  case $key in
    1) protocol_name="ICMP" ;;
    6) protocol_name="TCP" ;;
    17) protocol_name="UDP" ;;
    58) protocol_name="ICMPv6" ;;
    *) protocol_name="Protocol $key" ;;
  esac

  # Only print if value is greater than zero
  if [ "$value" -gt 0 ]; then
    echo "$protocol_name: $value packets"
  fi
done


sudo ip netns exec r1 ip route del 192.168.20.2/32
sleep 2
destroy_net
