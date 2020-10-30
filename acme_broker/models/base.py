from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.inspection import inspect

Base = declarative_base()


def __repr__(self):
    attrs = [attr for attr in inspect(self).attrs.keys() if not issubclass(type(getattr(self, attr)), Base)]
    attrs_repr = [f'{attr}={getattr(self, attr)}' for attr in attrs]
    return f"<{type(self).__name__}=({','.join(attrs_repr)})>"


Base.__repr__ = __repr__


class Serializer(object):
    __serialize__ = []

    def serialize(self, request=None):
        return {c: getattr(self, c) for c in inspect(self).attrs.keys() if c in self.__serialize__}

    @staticmethod
    def serialize_list(l, request=None):
        return [m.serialize(request=request) for m in l]
