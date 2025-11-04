from aiohttp import web


class ServiceBase:
    def __init__(self, **kwargs):
        # Accept and ignore any kwargs to support cooperative multiple inheritance
        super().__init__()

    async def on_startup(self, app: web.Application):
        pass

    async def on_run(self, app: web.Application):
        pass

    async def on_shutdown(self, app: web.Application):
        pass

    async def on_cleanup(self, app: web.Application):
        pass
