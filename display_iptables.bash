#!/bin/bash

echo "FILTER table:"
iptables -t filter -L -nv
echo
echo


echo "NAT table:"
iptables -t nat -L -nv
echo
echo

echo "MANGLE table:"
iptables -t mangle -L -nv
echo
echo

echo "RAW table:"
iptables -t raw -L -nv
echo
echo
