import asyncio
import logging
import logging.config
from pathlib import Path

import click
import yaml

from acme_broker import AcmeBroker
from acme_broker.client import AcmeClient, InfobloxClient
from acme_broker.server import (
    AcmeServerBase,
    AcmeCA,
    RequestIPDNSChallengeValidator,
)
from acme_broker.util import generate_root_cert, generate_rsa_key

logger = logging.getLogger(__name__)


server_apps = {app.config_name: app for app in AcmeServerBase.subclasses}


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
    # TODO: separate account key function
    """Generates a self-signed root key pair/cert for the CA
    and an account key pair for the broker client"""
    click.echo("Generating root key pair/cert")
    # TODO: swap out info
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
@click.option("--config-file", envvar="APP_CONFIG_FILE", type=click.Path())
@click.option("--path", type=click.Path())
def run(config_file, path):
    """Starts the app as defined in the config file"""
    config = load_config(config_file)

    app_config_name = list(config.keys())[0]

    if app_config_name not in server_apps.keys():
        raise click.UsageError(
            f"Cannot run app '{app_config_name}'. Valid options: "
            f"{', '.join([app for app in server_apps.keys()])}. "
            f"Please check your config file '{config_file}' and rename the main section accordingly."
        )

    loop = asyncio.get_event_loop()

    app_class = server_apps[app_config_name]

    click.echo(f"Starting {app_class.__name__} at {path}")

    if app_class is AcmeBroker:
        loop.run_until_complete(run_broker(config, path))
    elif app_class is AcmeCA:
        loop.run_until_complete(run_ca(config, path))


async def run_ca(config, path):
    _, ca = await AcmeCA.unix_socket(config["ca"], path)
    ca.register_challenge_validator(RequestIPDNSChallengeValidator())

    while True:
        await asyncio.sleep(3600)


async def run_broker(config, path):
    infoblox_client = InfobloxClient(**config["broker"]["client"]["infoblox"])
    await infoblox_client.connect()

    broker_client = AcmeClient(
        directory_url=config["broker"]["client"]["directory"],
        private_key=config["broker"]["client"]["private_key"],
        contact=config["broker"]["client"]["contact"],
    )

    broker_client.register_challenge_solver(infoblox_client)

    await broker_client.start()
    _, broker = await AcmeBroker.unix_socket(
        config["broker"], path, client=broker_client
    )
    broker.register_challenge_validator(RequestIPDNSChallengeValidator())

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    main()
