FROM python:3.9

RUN apt-get update \
    && apt-get install -y supervisor

COPY acmetk /app/acmetk
COPY requirements.txt app_entrypoint.sh setup.py README.md /app/

VOLUME /var/log/supervisor

WORKDIR /app

RUN pip install --use-feature=2020-resolver -r requirements.txt \
    && pip install . \
    && chmod 700 acmetk/main.py app_entrypoint.sh

EXPOSE 8180
EXPOSE 8181

ENTRYPOINT ["/app/app_entrypoint.sh"]
