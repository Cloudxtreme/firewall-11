#!/bin/bash

##########

IPTABLES=/sbin/iptables
iface_ME=lo
iface_LAN=eth0
iface_WAN=wlan0

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

function fw_critical {
    # allow packets inbound/outbound to/from internal network that are RESTABLISHED,RELATED
    $IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    $IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    $IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    # anti-spoofing - no packets from internet claiming to be from internal network
    $IPTABLES -A INPUT -i $iface_WAN -s 10.1.1.1 -j DROP
    $IPTABLES -A INPUT -i $iface_WAN -s 10.1.1.0/24 -j DROP
    $IPTABLES -A INPUT -i $iface_WAN -s 127.0.0.1 -j DROP
    $IPTABLES -A INPUT -i $iface_WAN -s 127.0.0.0/8 -j DROP

    # drop fragments to prevent kernel panic
    $IPTABLES -A INPUT -f -j DROP

    # only allow SYN packets with a state of NEW
    $IPTABLES -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

    # drop inbound malformed NULL packets
    $IPTABLES -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

    # syn flood prevention
    $IPTABLES -N syn_flood
    $IPTABLES -A INPUT -p tcp --syn -m state --state NEW -j syn_flood
    $IPTABLES -A syn_flood -m limit --limit 5/s --limit-burst 10 -j RETURN
    $IPTABLES -A syn_flood -j DROP

    # can never remember which is which reply/request input/output
    $IPTABLES -A INPUT -p icmp --icmp-type echo-reply -m limit --limit  2/s --limit-burst 3 -j ACCEPT
    $IPTABLES -A INPUT -p icmp --icmp-type echo-request -m limit --limit  2/s --limit-burst 3 -j ACCEPT

}

function fw_set_policy {
    $IPTABLES -t filter -P OUTPUT ACCEPT
    $IPTABLES -t filter -P INPUT DROP
    $IPTABLES -t filter -P FORWARD DROP

    $IPTABLES -t nat -P PREROUTING ACCEPT
    $IPTABLES -t nat -P OUTPUT ACCEPT
    $IPTABLES -t nat -P INPUT ACCEPT
    $IPTABLES -t nat -P POSTROUTING ACCEPT

    $IPTABLES -t mangle -P PREROUTING ACCEPT
    $IPTABLES -t mangle -P OUTPUT ACCEPT
    $IPTABLES -t mangle -P INPUT ACCEPT
    $IPTABLES -t mangle -P POSTROUTING ACCEPT

    $IPTABLES -t raw -P PREROUTING ACCEPT
    $IPTABLES -t raw -P OUTPUT ACCEPT
}

function fw_OUTPUT {
    # NOTE OUTPUT POLICY IS ACCEPT
    echo

    # allow all outbound failsafe
#    $IPTABLES -A OUTPUT -o $iface_ME -m state --state NEW -j ACCEPT
#    $IPTABLES -A OUTPUT -o $iface_LAN -m state --state NEW -j ACCEPT
#    $IPTABLES -A OUTPUT -o $iface_WAN -m state --state NEW -j ACCEPT

    # icmp request outbound
#    $IPTABLES -A OUTPUT -p icmp -j ACCEPT
}

function fw_INPUT {
    # from me to me
    $IPTABLES -A INPUT -i $iface_ME -j ACCEPT
    $IPTABLES -A INPUT -s 128.0.0.0/8 -j ACCEPT
    $IPTABLES -A INPUT -s 10.1.1.1 -j ACCEPT

    # SSH
    $IPTABLES -A INPUT -p tcp -m tcp -s 10.1.1.0/24 --dport 22 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s 10.1.1.0/24 --dport 22 -m state --state NEW -j ACCEPT

    # FTP
    # NOTE: There is a difference between active (using intranet) and passive (using internet)
    $IPTABLES -A INPUT -p tcp -m tcp -s 10.1.1.0/24 --dport 20:21 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s 10.1.1.0/24 --dport 20:21 -m state --state NEW -j ACCEPT

    # DNS
    $IPTABLES -A INPUT -p tcp -m tcp -s 10.1.1.0/24 --dport 53 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s 10.1.1.0/24 --dport 53 -m state --state NEW -j ACCEPT

    # DNS also
    $IPTABLES -A INPUT -p tcp -m tcp -s 10.1.1.0/24 --dport 953 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s 10.1.1.0/24 --dport 953 -m state --state NEW -j ACCEPT

    # SQUID (HTTP proxy)
    $IPTABLES -A INPUT -p tcp -m tcp -s 10.1.1.0/24 --dport 4444 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s 10.1.1.0/24 --dport 4444 -m state --state NEW -j ACCEPT

    # VNC
    $IPTABLES -A INPUT -p tcp -m tcp -s 10.1.1.0/24 --dport 5900 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s 10.1.1.0/24 --dport 5900 -m state --state NEW -j ACCEPT

    # emergency bypass/backdoor
    $IPTABLES -A INPUT -s 10.1.1.2 -j ACCEPT
}

function fw_FORWARD {
    # allow outbound icmp from internal network
    $IPTABLES -A FORWARD -s 127.0.0.1 -p icmp -j ACCEPT
    $IPTABLES -A FORWARD -s 127.0.0.0/8 -p icmp -j ACCEPT
    $IPTABLES -A FORWARD -s 10.1.1.0/24 -p icmp -j ACCEPT


    # allow traffic on these ports
    $IPTABLES -A FORWARD -p tcp -m tcp --dport 80 -s 10.1.1.0/24 -m state --state NEW -j ACCEPT
    $IPTABLES -A FORWARD -p udp -m udp --dport 80 -s 10.1.1.0/24 -m state --state NEW -j ACCEPT

    $IPTABLES -A FORWARD -p tcp -m tcp --dport 443 -s 10.1.1.0/24 -m state --state NEW -j ACCEPT
    $IPTABLES -A FORWARD -p udp -m udp --dport 443 -s 10.1.1.0/24 -m state --state NEW -j ACCEPT

    $IPTABLES -A FORWARD -p tcp -m tcp --dport 20:21 -s 10.1.1.0/24 -m state --state NEW -j ACCEPT
    $IPTABLES -A FORWARD -p udp -m udp --dport 20:21 -s 10.1.1.0/24 -m state --state NEW -j ACCEPT
}

function fw_NAT {
    $IPTABLES -t nat -A POSTROUTING -o $iface_WAN -s 10.1.1.0/24 -j MASQUERADE
}

function fw_portforwarding {
#    $IPTABLES -t nat -A PREROUTING -p tcp -i $iface_WAN --dport 60000 -j DNAT --to-destination 10.3.3.2:60000
#    $IPTABLES -A FORWARD -p tcp -d 10.3.3.2 --dport 60000 -m state --state NEW -j ACCEPT
    echo
}

##########

echo "Setting environment"
fw_set_env

echo "Flushing"
fw_flush

echo "Doing critical"
fw_critical

echo "Setting policy"
fw_set_policy

echo "Configuring OUTPUT"
fw_OUTPUT

echo "Configuring INPUT"
fw_INPUT

echo "Configuring FORWARD"
fw_FORWARD

echo "Setting up NAT"
fw_NAT

echo "Enabling port forwarding"
fw_portforwarding

echo
echo "DONE."