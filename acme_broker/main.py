import asyncio
import logging
import logging.config
from pathlib import Path

import click
import yaml

import sys

sys.path.append("/app/")  # for supervisord inside docker

from acme_broker import AcmeBroker  # noqa
from acme_broker.client import AcmeClient  # noqa
from acme_broker.client.client import ChallengeSolverType, InfobloxClient  # noqa
from acme_broker.server import AcmeCA  # noqa
from acme_broker.util import generate_root_cert, generate_rsa_key  # noqa

logger = logging.getLogger(__name__)


def load_config(config_file):
    with open(config_file, "r") as stream:
        config = yaml.safe_load(stream)

    logging.config.dictConfig(config["logging"])
    return config


@click.group()
@click.pass_context
def main(ctx):
    pass


@main.command()
@click.argument("root-key-file", type=click.Path())
@click.argument("account-key-file", type=click.Path())
def generate_keys(root_key_file, account_key_file):
    """Generates a self-signed root key pair/cert for the CA
    and an account key pair for the broker client"""
    click.echo("Generating root key pair/cert")
    generate_root_cert(
        Path(root_key_file),
        "DE",
        "Lower Saxony",
        "Hanover",
        "ACME Broker",
        "ACMEBroker",
    )

    click.echo("Generating broker client key pair")
    generate_rsa_key(account_key_file)


@main.command()
@click.argument("config-file", type=click.Path())
def ca(config_file):
    """Starts the ACME CA"""
    config = load_config(config_file)
    click.echo(f'Starting ACME CA on port {config["ca"]["port"]}')

    async def serve_forever():
        await AcmeCA.runner(config["ca"])

        while True:
            await asyncio.sleep(3600)

    asyncio.run(serve_forever())


@main.command()
@click.argument("config-file", type=click.Path())
@click.argument("path", type=click.Path())
def broker(config_file, path):
    """Starts the ACME Broker"""
    config = load_config(config_file)
    click.echo(f"Starting ACME Broker at {path}")

    loop = asyncio.get_event_loop()

    async def serve_forever():
        infoblox_client = InfobloxClient(**config["broker"]["infoblox"])
        await infoblox_client.connect()

        broker_client = AcmeClient(
            directory_url=config["broker"]["client"]["directory"],
            private_key=config["broker"]["client"]["private_key"],
            contact=config["broker"]["client"]["contact"],
        )

        broker_client.register_challenge_solver(
            (ChallengeSolverType.DNS_01,),
            infoblox_client,
        )

        await broker_client.start()
        await AcmeBroker.unix_socket(config["broker"], path, client=broker_client)

        while True:
            await asyncio.sleep(3600)

    loop.run_until_complete(serve_forever())


if __name__ == "__main__":
    main()
