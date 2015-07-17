#!/bin/bash

##########

IPTABLES=/sbin/iptables
iface_ME=lo
iface_LAN=eth0
iface_WAN=eth1

net_ME=127.0.0.0/8
net_LAN=192.168.1.0/24
net_LAN2=192.168.2.0/24
#net_WAN=

ip_ME=127.0.0.1
ip_LAN_firewall=192.168.1.1
ip_BACKDOOR=192.168.1.2

###########

function fw_set_env {
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 0 > /proc/sys/net/ipv4/conf/all/forwarding
    echo 0 > /proc/sys/net/ipv4/conf/default/forwarding
    echo 0 > /proc/sys/net/ipv4/conf/lo/forwarding
    echo 1 > /proc/sys/net/ipv4/conf/eth0/forwarding
    echo 1 > /proc/sys/net/ipv4/conf/eth1/forwarding
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

function fw_custom_chains {
    $IPTABLES -N syn_flood
    $IPTABLES -A syn_flood -m limit --limit 2/s --limit-burst 10 -j RETURN
    $IPTABLES -A syn_flood -j LOG --log-prefix "-- SYN_FLOOD -- " --log-level debug
    $IPTABLES -A syn_flood -j DROP

    $IPTABLES -N logdrop
    $IPTABLES -A logdrop -j LOG --log-prefix "-- LOGDROP -- " --log-level debug
    $IPTABLES -A logdrop -j DROP
    
    $IPTABLES -N justlog
    $IPTABLES -A justlog -j LOG --log-prefix "-- JUSTLOG -- " --log-level debug

    $IPTABLES -N anti_spoof
    $IPTABLES -A anti_spoof -j LOG --log-prefix "-- SPOOF -- " --log-level debug
    $IPTABLES -A anti_spoof -j DROP
}

function fw_critical {
    # allow packets inbound/outbound to/from internal network that are RESTABLISHED,RELATED
    $IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    $IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    $IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    # anti-spoofing - no packets from internet claiming to be from internal network
    $IPTABLES -A INPUT -i $iface_WAN -s $net_ME -j anti_spoof
    $IPTABLES -A INPUT -i $iface_WAN -s $net_LAN -j anti_spoof
    $IPTABLES -A INPUT -i $iface_WAN -s $net_LAN2 -j anti_spoof

    # drop fragments to prevent kernel panic
    $IPTABLES -A INPUT -f -j DROP

    # only allow SYN packets with a state of NEW
    $IPTABLES -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

    # drop inbound malformed NULL packets
    $IPTABLES -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

    # syn flood prevention
    $IPTABLES -A INPUT -p tcp --syn -m state --state NEW -j syn_flood

    # can never remember which is which reply/request input/output
#    $IPTABLES -A INPUT -p icmp --icmp-type echo-reply -m limit --limit  2/s --limit-burst 3 -j ACCEPT
#    $IPTABLES -A INPUT -p icmp --icmp-type echo-request -m limit --limit  2/s --limit-burst 3 -j ACCEPT

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
    $IPTABLES -A INPUT -s $net_ME -j ACCEPT
    $IPTABLES -A INPUT -s $ip_ME -j ACCEPT

    if [ -e bannedip ]; then
	for ip in $(cat bannedip); do
	    $IPTABLES -A INPUT -s $ip -j logdrop
	done
    fi

    # SSH
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN --dport 22 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN --dport 22 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN2 --dport 22 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN2 --dport 22 -m state --state NEW -j ACCEPT

    # WWW
    $IPTABLES -A INPUT -p tcp -m tcp --dport 80 -m state --state NEW -j ACCEPT
#    $IPTABLES -A INPUT -p udp -m udp --dport 80 -m state --state NEW -j ACCEPT

    # FTP
    # NOTE: There is a difference between active (using intranet) and passive (using internet)
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN --dport 20:21 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN --dport 20:21 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN2 --dport 20:21 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN2 --dport 20:21 -m state --state NEW -j ACCEPT

    # DNS
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN --dport 53 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN --dport 53 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN2 --dport 53 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN2 --dport 53 -m state --state NEW -j ACCEPT

    # DNS also
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN --dport 953 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN --dport 953 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN2 --dport 953 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN2 --dport 953 -m state --state NEW -j ACCEPT

    # VNC
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN --dport 5900:5910 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN --dport 5900:5910 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN2 --dport 5900:5910 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN2 --dport 5900:5910 -m state --state NEW -j ACCEPT

    # MySQL
    # - due to MySQL listening on 127.0.0.1:3306
    # - we are accepting: $IPTABLES -A INPUT -i lo -j ACCEPT
    # - this may be redundant?
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_ME --dport 3606 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_ME --dport 3606 -m state --state NEW -j ACCEPT

    # DHCP Server
    $IPTABLES -A INPUT -p tcp -m tcp -s $net_LAN --dport 67 -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $net_LAN --dport 67 -m state --state NEW -j ACCEPT

    # emergency bypass/backdoor
    $IPTABLES -A INPUT -p tcp -m tcp -s $ip_BACKDOOR -m state --state NEW -j ACCEPT
    $IPTABLES -A INPUT -p udp -m udp -s $ip_BACKDOOR -m state --state NEW -j ACCEPT

    # Log ICMP traffic
    $IPTABLES -A INPUT -p icmp -j logdrop
}

function fw_FORWARD {
    # allow outbound icmp from internal network
#    $IPTABLES -A FORWARD -s $ip_ME -p icmp -j ACCEPT
#    $IPTABLES -A FORWARD -s $ip_LAN -p icmp -j ACCEPT
#    $IPTABLES -A FORWARD -s $net_ME -p icmp -j ACCEPT
#    $IPTABLES -A FORWARD -s $net_LAN -p icmp -j ACCEPT
#    $IPTABLES -A FORWARD -s $net_LAN2 -p icmp -j ACCEPT

    # allow traffic on these ports
    $IPTABLES -A FORWARD -p tcp -m tcp -s $net_LAN -m state --state NEW -j ACCEPT
    $IPTABLES -A FORWARD -p udp -m udp -s $net_LAN -m state --state NEW -j ACCEPT
    $IPTABLES -A FORWARD -p tcp -m tcp -s $net_LAN2 -m state --state NEW -j ACCEPT
    $IPTABLES -A FORWARD -p udp -m udp -s $net_LAN2 -m state --state NEW -j ACCEPT
}

function fw_NAT {
    $IPTABLES -t nat -A POSTROUTING -o $iface_WAN -s $net_LAN -j MASQUERADE
#    $IPTABLES -t nat -A POSTROUTING -o $iface_WAN -s $net_LAN2 -j MASQUERADE
}

function fw_portforwarding {
#    $IPTABLES -t nat -A PREROUTING -p tcp -i $iface_WAN --dport 8080 -j DNAT --to-destination 192.168.3.2:8080
#    $IPTABLES -A FORWARD -p tcp -d 192.168.3.2 --dport 8080 -m state --state NEW -j ACCEPT
    echo
}

##########

echo "Setting environment"
fw_set_env

echo "Flushing"
fw_flush

echo "Setting policy"
fw_set_policy

echo "Custom Chains"
fw_custom_chains

echo "Doing critical"
fw_critical

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
