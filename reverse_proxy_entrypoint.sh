#!/usr/bin/env bash

# Need to chown here again because the outside directory is always owned by root
chown www-data: /etc/resty-auto-ssl
/usr/local/openresty/nginx/sbin/nginx -g "daemon off; master_process on;"
