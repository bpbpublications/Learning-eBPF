#!/bin/bash

# Function to run a test case
run_test_case() {
  local family=$1
  local type=$2
  local expected_result=$3
  local nc_opts=""

  # Determine nc options based on family and type
  case "$family" in
    AF_INET)
      nc_opts="-4"
    ;;
    AF_INET6)
      nc_opts="-6"
    ;;
    *)
      echo "Unsupported family: $family"
      return 1
    ;;
  esac

  case "$type" in
    SOCK_STREAM)
      nc_opts="$nc_opts -l" # -l for listening
    ;;
    SOCK_DGRAM)
      nc_opts="$nc_opts -u -l" # -u for UDP, -l for listening
    ;;
    *)
      echo "Unsupported type: $type"
      return 1
    ;;
  esac

  # Run nc to create a listening socket in the background
  nc_pid=$(nc $nc_opts -p 0 & echo $!)

  # Get the socket's file descriptor (this might need adjustments depending on your system)
  sock_fd=$(lsof -t -a -p $nc_pid)

  # Attach the BPF program to the socket's cgroup
  bpftool cgroup attach /sys/fs/cgroup/socket/$sock_fd bind $prog_fd

  # Attempt a bind operation (the actual address doesn't matter here)
  bind_result=$(nc -w 1 $nc_opts -p 0 127.0.0.1 2>&1)

  # Check the result
  if [[ $bind_result == *"Permission denied"* && $expected_result == 1 ]]; then
    echo "Test passed: bind blocked as expected (family=$family, type=$type)"
  elif [[ $bind_result == "" && $expected_result == 0 ]]; then
    echo "Test passed: bind allowed as expected (family=$family, type=$type)"
  else
    echo "Test failed: unexpected result (family=$family, type=$type, result=$bind_result)"
  fi

  kill $nc_pid
}

# Test cases (same as before)
run_test_case AF_INET SOCK_STREAM 1
run_test_case AF_INET SOCK_DGRAM 0
run_test_case AF_INET6 SOCK_STREAM 0
