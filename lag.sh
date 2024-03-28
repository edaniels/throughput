#!/bin/bash

sudo pfctl -E
sudo dnctl -q flush
sudo pfctl -f /etc/pf.conf
sudo dnctl pipe 1 config bw 10Mbit/s delay 20 plr .05
echo "dummynet out proto { udp tcp } from any to any port { 1234 1235 } pipe 1" | sudo pfctl -f -
echo "dummynet in proto { udp tcp } from any to any port { 1234 1235 } pipe 1" | sudo pfctl -f -
