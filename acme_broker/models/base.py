from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.inspection import inspect


Base = declarative_base()


class Serializer(object):
    def serialize(self):
        return {c: getattr(self, c) for c in inspect(self).attrs.keys()}

    @staticmethod
    def serialize_list(l):
        return [m.serialize() for m in l]
