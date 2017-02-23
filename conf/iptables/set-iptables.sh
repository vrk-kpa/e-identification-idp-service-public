#!/bin/bash
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
apt-get install iptables-persistent
/sbin/iptables -A FORWARD -p tcp --destination-port 80 -j ACCEPT && /sbin/iptables -t nat -A PREROUTING -j REDIRECT -p tcp --destination-port 80 --to-ports 8080
/sbin/iptables -A FORWARD -p tcp --destination-port 443 -j ACCEPT && /sbin/iptables -t nat -A PREROUTING -j REDIRECT -p tcp --destination-port 443 --to-ports 8443
iptables-save > /etc/iptables/rules.v4
