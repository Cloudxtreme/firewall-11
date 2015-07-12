#!/bin/bash

##########

IPTABLES=/sbin/iptables

###########

function fw_set_env {
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 0 > /proc/sys/net/ipv4/conf/all/forwarding
    echo 0 > /proc/sys/net/ipv4/conf/default/forwarding
    echo 0 > /proc/sys/net/ipv4/conf/lo/forwarding
    echo 1 > /proc/sys/net/ipv4/conf/eth0/forwarding
    echo 1 > /proc/sys/net/ipv4/conf/wlan0/forwarding
}

function fw_flush {
    echo "Current tables supported:"
    echo
    cat /proc/net/ip_tables_names
    echo

    $IPTABLES -t filter -F
    $IPTABLES -t nat -F
    $IPTABLES -t mangle -F
    $IPTABLES -t raw -F
#    $IPTABLES -t security -F

    $IPTABLES -t filter -X
    $IPTABLES -t nat -X
    $IPTABLES -t mangle -X
    $IPTABLES -t raw -X

    $IPTABLES -t filter --zero OUTPUT
    $IPTABLES -t filter --zero INPUT
    $IPTABLES -t filter --zero FORWARD

    $IPTABLES -t nat --zero PREROUTING
    $IPTABLES -t nat --zero OUTPUT
    $IPTABLES -t nat --zero INPUT
    $IPTABLES -t nat --zero POSTROUTING

    $IPTABLES -t mangle --zero PREROUTING
    $IPTABLES -t mangle --zero OUTPUT
    $IPTABLES -t mangle --zero INPUT
    $IPTABLES -t mangle --zero POSTROUTING

    $IPTABLES -t raw --zero OUTPUT
    $IPTABLES -t raw --zero PREROUTING

}

##########

echo "Setting environment"
fw_set_env

echo "Flushing"
fw_flush

echo
echo "DONE."