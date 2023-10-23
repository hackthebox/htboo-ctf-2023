#!/bin/ash

# Secure entrypoint
chmod 600 /entrypoint.sh

# Start application
/usr/bin/supervisord -c /etc/supervisord.conf