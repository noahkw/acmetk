import enum

from sqlalchemy import Column, Enum, String, Boolean

from .base import Base


class AccountStatus(enum.Enum):
    VALID = 'valid'
    DEACTIVATED = 'deactivated'
    REVOKED = 'revoked'


class Account(Base):
    __tablename__ = 'accounts'

    key = Column(String, primary_key=True)
    status = Column('status', Enum(AccountStatus))
    contact = Column(String)
    termsOfServiceAgreed = Column(Boolean)

    def __repr__(self):
        return f'<Account(key="{self.key}", status="{self.status}", contact="{self.contact}", ' \
               f'termsOfServiceAgreed="{self.termsOfServiceAgreed}")>'
