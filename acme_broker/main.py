import asyncio
import logging
import logging.config
import os

import click
import yaml

from acme_broker.server import AcmeCA

logger = logging.getLogger(__name__)


def load_config(config_file):
    with open(config_file, "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as e:
            print(e)

    logging.config.dictConfig(config["logging"])
    return config


@click.group()
@click.pass_context
def main(ctx):
    pass


@main.command()
@click.option("--debug/--no-debug", default=False)
@click.argument("config-file", type=click.Path())
def ca(debug, config_file):
    """Starts the ACME CA"""
    config = load_config(config_file)
    click.echo(f'Starting ACME CA on port {config["ca"]["port"]}')

    if not debug:

        async def serve_forever():
            _ = await AcmeCA.runner(*config["ca"].values())

            while True:
                await asyncio.sleep(3600)

        asyncio.run(serve_forever())
    else:
        # TODO: fix or remove
        os.system(r"adev runserver server/server.py")


if __name__ == "__main__":
    main()
