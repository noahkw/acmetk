from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.inspection import inspect

Base = declarative_base()


class Serializer(object):
    IGNORE = []

    def serialize(self):
        return {c: getattr(self, c) for c in inspect(self).attrs.keys() if c not in self.IGNORE}

    @staticmethod
    def serialize_list(l):
        return [m.serialize() for m in l]
