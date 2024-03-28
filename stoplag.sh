#!/bin/bash

sudo dnctl -q flush
sudo pfctl -f /etc/pf.conf
