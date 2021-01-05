FROM debian:buster

# To pin dehydrated to v0.6.6: (EC switch)
# https://raw.githubusercontent.com/dehydrated-io/dehydrated/589e9f30b383751a927d745e83c0c53bf42a195c/dehydrated

RUN apt-get update \
    && apt-get -y install --no-install-recommends build-essential wget gnupg ca-certificates \
    && wget -O - https://openresty.org/package/pubkey.gpg | apt-key add - \
    && codename=`grep -Po 'VERSION="[0-9]+ \(\K[^)]+' /etc/os-release` \
    && echo "deb http://openresty.org/package/debian $codename openresty" \
        | tee /etc/apt/sources.list.d/openresty.list \
    && apt-get update \
    && apt-get install -y openresty supervisor luarocks \
    && luarocks install lua-resty-auto-ssl \
    && mkdir /etc/resty-auto-ssl \
    && chown www-data: /etc/resty-auto-ssl \
    && curl https://raw.githubusercontent.com/dehydrated-io/dehydrated/master/dehydrated -o \
        /usr/local/bin/resty-auto-ssl/dehydrated \
    && openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
       -subj '/CN=sni-support-required-for-valid-ssl' \
       -keyout /etc/ssl/resty-auto-ssl-fallback.key \
       -out /etc/ssl/resty-auto-ssl-fallback.crt \
    && mkdir /etc/openresty/conf.d \
    && rm /etc/openresty/nginx.conf \
    && ln -sf /dev/stdout /usr/local/openresty/nginx/logs/access.log \
    && ln -sf /dev/stderr /usr/local/openresty/nginx/logs/error.log

COPY reverse_proxy_entrypoint.sh /

RUN chmod 700 /reverse_proxy_entrypoint.sh

VOLUME /etc/resty-auto-ssl

EXPOSE 80
EXPOSE 443

ENTRYPOINT ["/reverse_proxy_entrypoint.sh"]
