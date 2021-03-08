# not via pip available, therefore stolen
# https://github.com/wizeline/sqlalchemy-pagination.git

# The MIT License (MIT)
#
# Copyright (c) 2016 Wizeline
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import math

from aiohttp import web


class Page:
    def __init__(self, items, page, page_size, total):
        self.items = items
        self.previous_page = None
        self.next_page = None
        self.has_previous = page > 1
        if self.has_previous:
            self.previous_page = page - 1
        previous_items = (page - 1) * page_size
        self.has_next = previous_items + len(items) < total
        if self.has_next:
            self.next_page = page + 1
        self.total = total
        self.pages = int(math.ceil(total / float(page_size)))
        self.current_page = page


async def paginate(session, request, query, by="limit", total=-1, pms=None):
    if total is None:
        # None is passed at the changes endpoint if there are no changes yet.
        raise web.HTTPBadRequest(body="No changes have been logged.")

    page_size = int(request.query.get("pagesize", 25))
    if not (0 < page_size < 100):
        raise web.HTTPBadRequest(body=f"page_size ({page_size}) must be > 0 and < 100")

    page_count = max(math.ceil(total / page_size), 1)
    # min page_count is 1

    page = int(request.query.get("page", page_count))
    # min page is 1

    if not (0 < page <= page_count):
        raise web.HTTPBadRequest(
            body=f"page ({page}) must be between > 0 and <= {page_count}"
        )

    if by != "limit":
        # BETWEEN on indexed values is way faster …
        begin = (page - 1) * page_size
        end = max(page * page_size - 1, 0)
        q = query.filter(by.between(begin, end))
    else:
        begin = (page_count - page) * page_size
        q = query.limit(page_size).offset(begin)

    try:
        if pms:
            async with pms.measure():
                r = await session.execute(q)
        else:
            r = await session.execute(q)
        items = r.scalars().all()
        assert len(items) <= page_size

    except Exception as e:
        print(e)
        raise e

    return Page(items, page, page_size, total)
