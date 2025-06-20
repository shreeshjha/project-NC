#!/bin/bash

# include helper.bash file: used to provide some common function across testing scripts
source "${BASH_SOURCE%/*}/libs/helpers.bash"

# function cleanup: is invoked each time script exit (with or without errors)
function cleanup {
  set +e
  delete_veth 2
}
trap cleanup ERR

# Enable verbose output
set -x

cleanup
# Makes the script exit, at first error
# Errors are thrown by commands returning not 0 value
set -e

# Create two network namespaces and veth pairs
create_veth 2

# Get MAC address using ifconfig
mac1=$(sudo ip netns exec ns1 ifconfig veth1_ | grep ether | awk '{print $2}')
mac2=$(sudo ip netns exec ns2 ifconfig veth2_ | grep ether | awk '{print $2}')

# Update ARP table ns1
sudo ip netns exec ns1 arp -s 10.0.0.2 $mac2

# Update ARP table ns2
sudo ip netns exec ns2 arp -s 10.0.0.1 $mac1

sudo ip netns exec ns1 ./xdp_loader -i veth1_
sudo ip netns exec ns2 ./xdp_loader -i veth2_

# Disable RX and TX checksumming
# This is needed to avoid checksum errors when using XDP
sudo ip netns exec ns1 ethtool -K veth1_ rx off tx off
sudo ip netns exec ns2 ethtool -K veth2_ rx off tx off
