FROM python:3.9

RUN apt-get update && apt-get install -y nginx supervisor && rm /etc/nginx/sites-available/default && rm /etc/nginx/nginx.conf

COPY acme_broker /app/acme_broker
COPY prod.yml requirements.txt entrypoint.sh /app/

COPY ./docker_conf/nginx/conf.d /etc/nginx/conf.d
COPY ./docker_conf/nginx/nginx.conf /etc/nginx/nginx.conf
COPY ./docker_conf/supervisor/conf.d /etc/supervisor/conf.d

EXPOSE 5000

WORKDIR /app

RUN pip install -r requirements.txt
RUN chmod 700 acme_broker/main.py entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
