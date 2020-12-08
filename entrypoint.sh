#!/usr/bin/env bash

# Need to chown here again because the outside directory is always owned by root
chown www-data: /etc/resty-auto-ssl
supervisord -n -c /etc/supervisor/supervisord.conf
