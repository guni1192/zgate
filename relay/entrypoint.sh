#!/bin/bash
set -e

echo "Setting up NAT..."

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

echo "NAT configured. Starting Relay..."
exec "$@"
