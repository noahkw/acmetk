from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.inspection import inspect

Base = declarative_base()


class Serializer(object):
    IGNORE = []

    def serialize(self, request=None):
        return {c: getattr(self, c) for c in inspect(self).attrs.keys() if c not in self.IGNORE}

    @staticmethod
    def serialize_list(l, request=None):
        return [m.serialize(request=request) for m in l]
