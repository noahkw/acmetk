import asyncio
import logging
import logging.config
import subprocess
from pathlib import Path
from typing import Any

import click
import yaml
from pydantic import Field
from pydantic_settings import BaseSettings

from acmetk.client import ChallengeSolver
from acmetk.database import Database
from acmetk.plugin_base import PluginRegistry
from acmetk.server import (
    AcmeServerBase,
    AcmeRelayBase,
    AcmeCA,
    AcmeProxy,
    AcmeBroker,
    ChallengeValidator,
)
from acmetk.util import generate_root_cert, generate_rsa_key, generate_ec_key

logger = logging.getLogger(__name__)

PluginRegistry.load_plugins(r"plugins")
server_app_registry = PluginRegistry.get_registry(AcmeServerBase)
challenge_solver_registry = PluginRegistry.get_registry(ChallengeSolver)
challenge_validator_registry = PluginRegistry.get_registry(ChallengeValidator)

PATH_OR_HOST_AND_PORT_MSG = "Must specify either the path of the unix socket or the hostname + port."


class Config(BaseSettings, extra="forbid"):
    service: AcmeCA.Config | AcmeProxy.Config | AcmeBroker.Config = Field(discriminator="type")
    logging: Any


def load_config(config_file: str) -> Config:
    with open(config_file) as stream:
        config = yaml.safe_load(stream)

    return Config.model_validate(config)


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


def alembic_run(config: AcmeServerBase.Config) -> None:
    from alembic.config import Config as alembic_Config
    from alembic import command
    import yarl

    cfg = alembic_Config((base := Path(__file__).parent.parent) / "alembic.ini")
    cfg.set_main_option("script_location", str(base / "alembic"))
    db = str(yarl.URL(str(config.db)).with_scheme("postgresql+psycopg2"))
    cfg.set_section_option("alembic", "sqlalchemy.url", db)
    command.upgrade(cfg, Database.ALEMBIC_REVISION)


@main.command()
@click.option("--config-file", envvar="APP_CONFIG_FILE", type=click.Path())
@click.option("--bootstrap-port", type=click.INT)
@click.option("--path", type=click.Path())
@click.option("--alembic-upgrade", type=bool, default=False)
def run(
    config_file: str,
    bootstrap_port: int | None,
    path: str,
    alembic_upgrade: bool,
):
    """Starts the app as defined in the config file.

    Starts the app in bootstrap mode if the bootstrap port is set via --bootstrap-port.
    """
    config: Config = load_config(config_file)

    loop = asyncio.get_event_loop()

    app_cfg = config.service
    app_class = server_app_registry.get_plugin(app_cfg.type)

    if path:
        app_cfg.path = path

    if alembic_upgrade:
        alembic_run(app_cfg)

    if bootstrap_port:
        if app_class is AcmeCA:
            raise click.UsageError(f"Bootstrapping is not supported for the {app_class} at this moment.")

        click.echo(f"Starting {app_class.__name__} in bootstrap mode on port {bootstrap_port}")

        app_cfg.port = bootstrap_port
        app_cfg.challenge_validators = ["dummy"]  # Do not validate challenges
        app_cfg.subnets = [
            "127.0.0.1/32",
            "10.110.0.0/24",
        ]  # Only allow localhost and the docker bridge network
        # Bootstrap app does not run behind a reverse proxy:
        app_cfg.use_forwarded_header = False
        app_cfg.eab.require = False
    else:
        click.echo(f"Starting {app_class.__name__}")

    runner, site = loop.run_until_complete(run_app(app_class, app_cfg))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(runner.shutdown())
        loop.run_until_complete(runner.cleanup())


async def run_app(service_cls: type[AcmeServerBase | AcmeRelayBase], config: AcmeCA.Config):
    runner, ca = await service_cls.runner(config)
    return runner, ca


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
def init(connection_string: str, password: str):
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
def drop(connection_string: str, password: str):
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
