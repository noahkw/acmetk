import asyncio
import logging
import logging.config
import subprocess
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
from acmetk.util import generate_root_cert, generate_rsa_key, generate_ec_key, names_of

logger = logging.getLogger(__name__)

PluginRegistry.load_plugins(r"plugins")
server_app_registry = PluginRegistry.get_registry(AcmeServerBase)
challenge_solver_registry = PluginRegistry.get_registry(ChallengeSolver)
challenge_validator_registry = PluginRegistry.get_registry(ChallengeValidator)

PATH_OR_HOST_AND_PORT_MSG = "Must specify either the path of the unix socket or the hostname + port."


def load_config(config_file: str) -> dict:
    with open(config_file) as stream:
        config = yaml.safe_load(stream)

    if logging_section := config.get("logging"):
        logging.config.dictConfig(logging_section)

    return config


def create_challenge_solver(config):
    challenge_solver_name = list(config.keys())[0]

    challenge_solver_class = challenge_solver_registry.get_plugin(challenge_solver_name)

    if type(kwargs := config[challenge_solver_name]) is not dict:
        kwargs = {}

    challenge_solver = challenge_solver_class(**kwargs)

    return challenge_solver


def create_challenge_validator(challenge_validator_name):
    challenge_validator_class = challenge_validator_registry.get_plugin(challenge_validator_name)
    return challenge_validator_class()


def create_challenge_validators(challenge_validator_names: list[str]):
    return [create_challenge_validator(name) for name in challenge_validator_names]


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
    from alembic.config import Config
    from alembic import command
    import yarl

    cfg = Config((base := Path(__file__).parent.parent) / "alembic.ini")
    cfg.set_main_option("script_location", str(base / "alembic"))
    db = str(yarl.URL(config.db).with_scheme("postgresql+psycopg2"))
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
    config = load_config(config_file)

    loop = asyncio.get_event_loop()

    app_config_name = list(config.keys())[0]

    try:
        app_class: AcmeServerBase = server_app_registry.get_plugin(app_config_name)
    except ValueError as e:
        raise click.UsageError(*e.args)

    app_config = config.get(app_config_name)
    app_cfg = app_class.Config(**app_config)

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
        app_cfg.require_eab = False
    else:
        click.echo(f"Starting {app_class.__name__}")

    if issubclass(app_class, AcmeRelayBase):
        runner, site = loop.run_until_complete(run_relay(app_cfg, path, app_class))
    elif app_class is AcmeCA:
        runner, site = loop.run_until_complete(run_ca(app_cfg, path))
    else:
        raise ValueError(app_class)

    aiohttp_jinja2.setup(site.app, loader=jinja2.FileSystemLoader("./tpl/"))
    aiohttp_jinja2.get_env(site.app).globals.update({"url_for": _url_for, "names_of_csr": names_of})

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(runner.cleanup())


async def run_ca(config: AcmeCA.Config, path: str):
    challenge_validators = create_challenge_validators(config.challenge_validators)

    if path:
        runner, ca = await AcmeCA.unix_socket(config, path)
    elif config.hostname and config.port:
        runner, ca = await AcmeCA.runner(config)
    else:
        raise click.UsageError(PATH_OR_HOST_AND_PORT_MSG)

    ca.register_challenge_validators(challenge_validators)

    return runner, ca


@jinja2.pass_context
def _url_for(context, __route_name, **parts):
    try:
        return context["request"].match_info.apps[-1].router[__route_name].url_for(**parts)
    except Exception as e:
        print(e)
        return "ERROR GENERATING URL"


async def run_relay(config: AcmeRelayBase.Config, path: str, class_: AcmeRelayBase):
    try:
        challenge_solver = create_challenge_solver(config.client.challenge_solver)
        challenge_validators = create_challenge_validators(config.challenge_validators)

    except ValueError as e:
        raise click.UsageError(*e.args)

    relay_client = AcmeClient(config.client)

    relay_client.register_challenge_solver(challenge_solver)

    await relay_client.start()

    if path:
        runner, relay = await class_.unix_socket(config, path, client=relay_client)
    elif config.hostname and config.port:
        runner, relay = await class_.runner(config, client=relay_client)
    else:
        raise click.UsageError(PATH_OR_HOST_AND_PORT_MSG)

    relay.register_challenge_validators(challenge_validators)

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
