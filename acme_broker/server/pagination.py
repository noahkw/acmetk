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

async def paginate(session, request, query, by='limit', total=-1):
    page_size = int(request.query.get("pagesize", 25))
    page = int(request.query.get("page", 1))
    if not ( 0 < page_size < 100) :
        raise AttributeError("0 < page_size < 100")
    page_count = math.ceil(total / page_size)
    if not ( 0 < page <= page_count):
        raise AttributeError(f"0 < page < {page_count}")

    begin = (page - 1) * page_size
    end = page * page_size
    if by == 'limit':
        q = query.limit(page_size).offset(begin)
    else:
        q = query.filter(by.between(begin, end))
    print(q.compile(compile_kwargs={"literal_binds": True}))
    try:
        r = await session.execute(q)
        items = r.scalars().all()
    except Exception as e:
        print(e)

    return Page(items, page, page_size, total)
