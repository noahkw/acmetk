import asyncio
import logging
import logging.config
import subprocess
import sys
from pathlib import Path

import aiohttp_jinja2
import click
import jinja2
import yaml

from acmetk.client import AcmeClient, ChallengeSolver
from acmetk.database import Database
from acmetk.plugin_base import PluginRegistry
from acmetk.server import (
    AcmeServerBase,
    AcmeRelayBase,
    AcmeCA,
    ChallengeValidator,
)
from acmetk.util import generate_root_cert, generate_rsa_key, generate_ec_key

logger = logging.getLogger(__name__)

sys.path.append(r"./acmetk")

PluginRegistry.load_plugins(r"plugins")
server_app_registry = PluginRegistry.get_registry(AcmeServerBase)
challenge_solver_registry = PluginRegistry.get_registry(ChallengeSolver)
challenge_validator_registry = PluginRegistry.get_registry(ChallengeValidator)

PATH_OR_HOST_AND_PORT_MSG = (
    "Must specify either the path of the unix socket or the hostname + port."
)


def load_config(config_file):
    with open(config_file, "r") as stream:
        config = yaml.safe_load(stream)

    if logging_section := config.get("logging"):
        logging.config.dictConfig(logging_section)

    return config


async def create_challenge_solver(config):
    challenge_solver_name = list(config.keys())[0]

    try:
        challenge_solver_class = challenge_solver_registry.get_plugin(
            challenge_solver_name
        )
    except ValueError as e:
        raise click.UsageError(*e.args)

    if type((kwargs := config[challenge_solver_name])) is not dict:
        kwargs = {}

    challenge_solver = challenge_solver_class(**kwargs)
    await challenge_solver.connect()

    return challenge_solver


async def create_challenge_validator(challenge_validator_name):
    try:
        challenge_validator_class = challenge_validator_registry.get_plugin(
            challenge_validator_name
        )
    except ValueError as e:
        raise click.UsageError(*e.args)

    return challenge_validator_class()


@click.group()
@click.pass_context
def main(ctx):
    pass


@main.command()
def plugins():
    """Lists the available plugins and their respective config strings."""
    for plugins in [
        ("Server apps", server_app_registry.config_mapping()),
        ("Challenge solvers", challenge_solver_registry.config_mapping()),
        ("Challenge validators", challenge_validator_registry.config_mapping()),
    ]:
        click.echo(
            f"{plugins[0]}: {', '.join([f'{app.__name__} ({config_name})' for config_name, app in plugins[1].items()])}"
        )


@main.command()
@click.argument("root-key-file", type=click.Path())
def generate_keys(root_key_file):
    """Generates a self-signed root key pair/cert for the CA."""
    click.echo("Generating root key pair/cert")
    # TODO: swap out info
    generate_root_cert(
        Path(root_key_file),
        "DE",
        "Lower Saxony",
        "Hanover",
        "ACME Toolkit",
        "ACMEToolkit",
    )


@main.command()
@click.argument("account-key-file", type=click.Path())
@click.option(
    "--key-type",
    "-k",
    type=click.Choice(["rsa", "ec"], case_sensitive=False),
    default="rsa",
    show_default=True,
)
def generate_account_key(account_key_file, key_type):
    """Generates an account key for the ACME client."""
    click.echo(f"Generating client key of type {key_type} at {account_key_file}.")
    account_key_file = Path(account_key_file)
    if key_type == "rsa":
        generate_rsa_key(account_key_file)
    else:
        generate_ec_key(account_key_file)


@main.command()
@click.option("--config-file", envvar="APP_CONFIG_FILE", type=click.Path())
@click.option("--bootstrap-port", type=click.INT)
@click.option("--path", type=click.Path())
def run(config_file, bootstrap_port, path):
    """Starts the app as defined in the config file.

    Starts the app in bootstrap mode if the bootstrap port is set via --bootstrap-port."""
    config = load_config(config_file)

    loop = asyncio.get_event_loop()

    app_config_name = list(config.keys())[0]

    try:
        app_class = server_app_registry.get_plugin(app_config_name)
    except ValueError as e:
        raise click.UsageError(*e.args)

    if bootstrap_port:
        if app_class is AcmeCA:
            raise click.UsageError(
                f"Bootstrapping is not supported for the {app_class} at this moment."
            )

        click.echo(
            f"Starting {app_class.__name__} in bootstrap mode on port {bootstrap_port}"
        )
        app_config = config[app_config_name]

        app_config["port"] = bootstrap_port
        app_config["challenge_validator"] = "dummy"  # Do not validate challenges
        app_config["subnets"] = [
            "127.0.0.1/32",
            "10.110.0.0/24",
        ]  # Only allow localhost and the docker bridge network
        # Bootstrap app does not run behind a reverse proxy:
        app_config["use_forwarded_header"] = False
        app_config["require_eab"] = False
    else:
        click.echo(f"Starting {app_class.__name__}")

    if issubclass(app_class, AcmeRelayBase):
        runner, site = loop.run_until_complete(
            run_relay(config, path, app_class, app_config_name)
        )
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
        return (
            context["request"].match_info.apps[-1].router[__route_name].url_for(**parts)
        )
    except Exception as e:
        print(e)
        return "ERROR GENERATING URL"


async def run_relay(config, path, class_, config_name):
    config_section = config[config_name]

    challenge_solver = await create_challenge_solver(
        config_section["client"]["challenge_solver"]
    )
    challenge_validator = await create_challenge_validator(
        config_section["challenge_validator"]
    )

    relay_client = AcmeClient(
        directory_url=config_section["client"]["directory"],
        private_key=config_section["client"]["private_key"],
        contact=config_section["client"]["contact"],
    )

    relay_client.register_challenge_solver(challenge_solver)

    await relay_client.start()

    if path:
        runner, relay = await class_.unix_socket(
            config_section, path, client=relay_client
        )
    elif config_section["hostname"] and config_section["port"]:
        runner, relay = await class_.runner(config_section, client=relay_client)
    else:
        raise click.UsageError(PATH_OR_HOST_AND_PORT_MSG)

    relay.register_challenge_validator(challenge_validator)

    return runner, relay


@main.group()
def db():
    """Commands to interact with the database."""
    pass


@db.command()
def migrate():
    """Migrates the database."""
    click.echo("running migrations")
    subprocess.run(["alembic", "upgrade", "head"])


@db.command()
@click.argument("connection-string", type=click.STRING)
@click.option("--password", type=click.STRING, prompt=True, hide_input=True)
def init(connection_string, password):
    """Initializes the database's tables.

    The user needs to have admin privileges, i.e. 'acme_admin' should be used."""
    db = Database(connection_string.format(password))

    click.echo("Initializing tables...")
    loop = asyncio.get_event_loop()
    loop.run_until_complete(db.begin())
    click.echo("OK.")


@db.command()
@click.argument("connection-string", type=click.STRING)
@click.option("--password", type=click.STRING, prompt=True, hide_input=True)
def drop(connection_string, password):
    """Drops the database's tables.

    Make sure to backup the database before running this command.
    """
    db = Database(connection_string.format(password))

    click.echo("Dropping tables...")
    loop = asyncio.get_event_loop()

    if click.confirm("Really drop all tables?"):
        loop.run_until_complete(db.drop())
        click.echo("OK.")
    else:
        click.echo("Aborting...")


if __name__ == "__main__":
    main()
