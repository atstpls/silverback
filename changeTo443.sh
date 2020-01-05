#!/bin/bash

sed -i 's/proto udp/proto tcp/' a.ovpn
sed -i 's/1337/443/' a.ovpn
sed -i 's/tls-auth/tls-crypt/' a.ovpn
