FROM python:3.9

RUN apt-get update \
    && apt-get -y install --no-install-recommends wget gnupg ca-certificates \
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
    && rm /etc/openresty/nginx.conf

COPY acme_broker /app/acme_broker
COPY requirements.txt entrypoint.sh setup.py README.md /app/

COPY docker_conf/openresty/conf.d /etc/openresty/conf.d
COPY docker_conf/openresty/nginx.conf /etc/openresty/nginx.conf
COPY docker_conf/supervisor/conf.d /etc/supervisor/conf.d

VOLUME /etc/resty-auto-ssl
VOLUME /var/log/supervisor

EXPOSE 80
EXPOSE 443

WORKDIR /app

RUN pip install -r requirements.txt \
    && pip install . \
    && chmod 700 acme_broker/main.py entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
