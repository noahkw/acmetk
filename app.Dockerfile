FROM python:3.9

RUN apt-get update \
    && apt-get install -y supervisor

COPY acme_broker /app/acme_broker
COPY requirements.txt app_entrypoint.sh setup.py README.md /app/

VOLUME /var/log/supervisor

WORKDIR /app

RUN pip install -r requirements.txt \
    && pip install . \
    && chmod 700 acme_broker/main.py app_entrypoint.sh

EXPOSE 8180
EXPOSE 8181

ENTRYPOINT ["/app/app_entrypoint.sh"]
