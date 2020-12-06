import asyncio
import logging
import logging.config
from pathlib import Path

import click
import yaml

import aiohttp_jinja2
import jinja2

from acme_broker import AcmeBroker
from acme_broker.client import AcmeClient, ChallengeSolver
from acme_broker.server import (
    AcmeServerBase,
    AcmeCA,
    ChallengeValidator,
)
from acme_broker.util import generate_root_cert, generate_rsa_key

logger = logging.getLogger(__name__)


server_apps = AcmeServerBase.config_mapping()
challenge_solvers = ChallengeSolver.config_mapping()
challenge_validators = ChallengeValidator.config_mapping()

PATH_OR_HOST_AND_PORT_MSG = (
    "Must specify either the path of the unix socket or the hostname + port."
)


def load_config(config_file):
    with open(config_file, "r") as stream:
        config = yaml.safe_load(stream)

    logging.config.dictConfig(config["logging"])
    return config


async def create_challenge_solver(config):
    challenge_solver_name = list(config.keys())[0]

    if challenge_solver_name not in (solver_names := challenge_solvers.keys()):
        raise click.UsageError(
            f"The challenge solver plugin {challenge_solver_name} does not exist. Valid options: "
            f"{', '.join([solver for solver in solver_names])}."
        )

    challenge_solver_class = challenge_solvers[challenge_solver_name]

    if type((kwargs := config[challenge_solver_name])) is not dict:
        kwargs = {}

    challenge_solver = challenge_solver_class(**kwargs)
    await challenge_solver.connect()

    return challenge_solver


async def create_challenge_validator(challenge_validator_name):
    if challenge_validator_name not in (validator_names := challenge_validators.keys()):
        raise click.UsageError(
            f"The challenge solver plugin {challenge_validator_name} does not exist. Valid options: "
            f"{', '.join([solver for solver in validator_names])}."
        )

    challenge_validator_class = challenge_validators[challenge_validator_name]

    return challenge_validator_class()


@click.group()
@click.pass_context
def main(ctx):
    pass


@main.command()
def plugins():
    """Lists the available plugins and their respective config strings."""
    for plugins in [
        ("Server apps", server_apps),
        ("Challenge solvers", challenge_solvers),
        ("Challenge validators", challenge_validators),
    ]:
        click.echo(
            f"{plugins[0]}: {', '.join([f'{app.__name__} ({config_name})' for config_name, app in plugins[1].items()])}"
        )


@main.command()
@click.argument("root-key-file", type=click.Path())
def generate_keys(root_key_file):
    """Generates a self-signed root key pair/cert for the CA"""
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


@main.command()
@click.argument("account-key-file", type=click.Path())
def generate_account_key(account_key_file):
    """Generates an account key for the ACME client"""
    click.echo(
        f"Generating client key at {account_key_file}.\nMake sure to change its permissions,"
        f" for example with: chmod 600 {account_key_file}"
    )
    generate_rsa_key(account_key_file)


@main.command()
@click.option("--config-file", envvar="APP_CONFIG_FILE", type=click.Path())
@click.option("--path", type=click.Path())
def run(config_file, path):
    """Starts the app as defined in the config file"""
    config = load_config(config_file)

    app_config_name = list(config.keys())[0]

    if app_config_name not in (app_names := server_apps.keys()):
        raise click.UsageError(
            f"Cannot run app '{app_config_name}'. Valid options: "
            f"{', '.join([app for app in app_names])}. "
            f"Please check your config file '{config_file}' and rename the main section accordingly."
        )

    loop = asyncio.get_event_loop()

    app_class = server_apps[app_config_name]

    click.echo(f"Starting {app_class.__name__}")

    if app_class is AcmeBroker:
        runner, site = loop.run_until_complete(run_broker(config, path))
    elif app_class is AcmeCA:
        runner, site = loop.run_until_complete(run_ca(config, path))
    else:
        raise ValueError(app_class)

    aiohttp_jinja2.setup(site.app, loader=jinja2.FileSystemLoader("./tpl/"))
    aiohttp_jinja2.get_env(site.app).globals.update({"url_for": _url_for})

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(runner.cleanup())

async def run_ca(config, path):
    challenge_validator = await create_challenge_validator(
        config["ca"]["challenge_validator"]
    )

    if path:
        runner, ca = await AcmeCA.unix_socket(config["ca"], path)
    elif config["ca"]["hostname"] and config["ca"]["port"]:
        runner, ca = await AcmeCA.runner(config["ca"])
    else:
        raise click.UsageError(PATH_OR_HOST_AND_PORT_MSG)

    ca.register_challenge_validator(challenge_validator)

    return runner, ca


@jinja2.contextfunction
def _url_for(context, __route_name, **parts):
    try:
        return context["request"].match_info.apps[-1].router[__route_name].url_for(**parts)
    except Exception as e:
        print(e)
        return "ERROR GENERATING URL"


async def run_broker(config, path):
    challenge_solver = await create_challenge_solver(
        config["broker"]["client"]["challenge_solver"]
    )
    challenge_validator = await create_challenge_validator(
        config["broker"]["challenge_validator"]
    )

    broker_client = AcmeClient(
        directory_url=config["broker"]["client"]["directory"],
        private_key=config["broker"]["client"]["private_key"],
        contact=config["broker"]["client"]["contact"],
    )

    broker_client.register_challenge_solver(challenge_solver)

    await broker_client.start()

    if path:
        runner, broker = await AcmeBroker.unix_socket(
            config["broker"], path, client=broker_client
        )
    elif config["broker"]["hostname"] and config["broker"]["port"]:
        runner, broker = await AcmeBroker.runner(config["broker"], client=broker_client)
    else:
        raise click.UsageError(PATH_OR_HOST_AND_PORT_MSG)

    broker.register_challenge_validator(challenge_validator)

    return runner, broker

if __name__ == "__main__":
    main()
