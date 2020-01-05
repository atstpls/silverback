#!/bin/bash
if [ "$#"  -ne 1 ]
  then
    echo "Must supply IP address as argument"
    exit
fi
ip=$1

nmap -Pn -p1-65535 -o tcp-$ip $ip -T 4 | grep -v 'filtered|closed'
for p in $(grep open tcp-$ip | cut -d "/" -f 1);do nmap -Pn -sV -p$p $ip -T 4 |grep open >> ver-$ip;done

nmap -Pn -sU -p1-65535 -o udp-$ip $ip -T 4 | grep -v 'filtered|closed'
for p in $(grep open udp-$ip | cut -d "/" -f 1);do nmap -Pn -sV -p$p $ip -T 4 |grep open >> ver-$ip;done
