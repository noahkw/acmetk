import asyncio
import logging
import logging.config
from pathlib import Path

import click
import yaml

import sys

sys.path.append("/app/")  # for supervisord inside docker

from acme_broker import AcmeBroker  # noqa
from acme_broker.client import AcmeClient, ChallengeSolverType, InfobloxClient  # noqa
from acme_broker.server import AcmeCA  # noqa
from acme_broker.util import generate_root_cert, generate_rsa_key  # noqa

logger = logging.getLogger(__name__)


APP_NAMES = ("broker", "ca")


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
@click.option("--config-file", envvar="APP_CONFIG_FILE", type=click.Path())
@click.option("--path", type=click.Path())
def run(config_file, path):
    """Starts the app as defined in the config file"""
    config = load_config(config_file)

    if (app := list(config.keys())[0]) not in APP_NAMES:
        raise click.UsageError(
            f"Cannot run app '{app}'. Valid options: {', '.join(APP_NAMES)}. "
            f"Please check your config file '{config_file}' and rename the main section accordingly."
        )

    loop = asyncio.get_event_loop()

    if app == "broker":
        loop.run_until_complete(run_broker(config, path))
    elif app == "ca":
        loop.run_until_complete(run_ca(config, path))


async def run_ca(config, path):
    click.echo(f"Starting ACME CA at {path}")
    await AcmeCA.unix_socket(config["ca"], path)

    while True:
        await asyncio.sleep(3600)


async def run_broker(config, path):
    click.echo(f"Starting ACME Broker at {path}")

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


if __name__ == "__main__":
    main()
