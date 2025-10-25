from aiohttp import web


class ServiceBase:
    async def on_startup(self, app: web.Application):
        pass

    async def on_run(self, app: web.Application):
        pass

    async def on_shutdown(self, app: web.Application):
        pass

    async def on_cleanup(self, app: web.Application):
        pass
