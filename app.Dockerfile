FROM python:3.9

RUN apt-get update \
    && apt-get install -y supervisor

COPY acmetk /app/acmetk
COPY tpl /app/tpl
COPY requirements.txt app_entrypoint.sh pyproject.toml README.md /app/
COPY alembic.ini /app/
COPY alembic /app/alembic

VOLUME /var/log/supervisor

WORKDIR /app

RUN pip install -r requirements.txt \
    && pip install . \
    && chmod 700 acmetk/main.py app_entrypoint.sh

EXPOSE 8180
EXPOSE 8181

ENTRYPOINT ["/app/app_entrypoint.sh"]
