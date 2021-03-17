import enum
import json
import typing

import OpenSSL
import acme.jws
import acme.messages
import josepy
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from josepy import JSONDeSerializable

from acmetk.models.account import AccountStatus
from acmetk.models.authorization import AuthorizationStatus

ERROR_CODE_STATUS = {
    "unauthorized": 401,
    "orderNotReady": 403,
    "accountDoesNotExist": 404,
}
"""ACME error types mapped to HTTP status codes.

`6.7. Errors <https://tools.ietf.org/html/rfc8555#section-6.7>`_
"""


def get_status(error_type: str) -> int:
    """Gets the HTTP status code that corresponds to the given ACME error type.

    Defaults to status code *400* for a generic user error if no mapping was defined by
    `RFC 8555 <https://tools.ietf.org/html/rfc8555>`_.

    :param error_type: The ACME error type.
    :return: The corresponding HTTP status code.
    """
    return ERROR_CODE_STATUS.get(error_type, 400)


def decode_cert(b64der):
    return x509.load_der_x509_certificate(josepy.json_util.decode_b64jose(b64der))


def encode_cert(cert):
    return josepy.encode_b64jose(
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
    )


class RevocationReason(enum.Enum):
    """Certificate revocation reasons.

    Defined in `5.3.1. Reason Code <https://tools.ietf.org/html/rfc5280#section-5.3.1>`_ of RFC 5280.
    """

    unspecified = 0
    keyCompromise = 1
    cACompromise = 2
    affiliationChanged = 3
    superseded = 4
    cessationOfOperation = 5
    certificateHold = 6
    # value 7 is unused
    removeFromCRL = 8
    privilegeWithdrawn = 9
    aACompromise = 10


class Revocation(josepy.JSONObjectWithFields):
    """Message type for certificate revocation requests."""

    certificate: "cryptography.x509.Certificate" = josepy.Field(
        "certificate", decoder=decode_cert, encoder=encode_cert
    )
    """The certificate to be revoked."""
    reason: RevocationReason = josepy.Field(
        "reason",
        decoder=RevocationReason,
        encoder=lambda reason: reason.value,
        omitempty=True,
    )
    """The reason for the revocation."""


def encode_csr(csr):
    # Encode CSR as JOSE Base-64 DER.
    return josepy.encode_b64jose(csr.public_bytes(encoding=serialization.Encoding.DER))


def decode_csr(b64der):
    return x509.load_der_x509_csr(josepy.json_util.decode_b64jose(b64der))


class CertificateRequest(josepy.JSONObjectWithFields):
    """Message type for certificate requests.

    Received by an :class:`~acmetk.server.AcmeServerBase` instance at the order finalization step
    :meth:`~acmetk.server.AcmeServerBase.finalize_order`.
    """

    csr: "cryptography.x509.CertificateSigningRequest" = josepy.Field(
        "csr", decoder=decode_csr, encoder=encode_csr
    )
    """The certificate signing request."""


class JSONDeSerializableAllowEmpty(JSONDeSerializable):
    """JSONDeSerializable that allows an empty string as the input for :func:`json_loads`.

    This subclass (sub-interface) is needed for :class:`AuthorizationUpdate` as well as
    :class:`AccountUpdate`, so the request payload can still be parsed into a valid (empty)
    update object although a POST-as-GET with an empty payload (:code:`b""`) was performed.
    """

    @classmethod
    def json_loads(cls, json_string: str) -> "JSONDeSerializable":
        """Deserialize from JSON document string.

        :param json_string: The json string to be deserialized.
        :return: The deserialized object whose type is a subclass of :class:`josepy.JSONDeSerializable`.
        """
        try:
            if len(json_string) == 0:
                loads = "{}"
            else:
                loads = json.loads(json_string)
        except ValueError as error:
            raise josepy.errors.DeserializationError(error)
        return cls.from_json(loads)


class AuthorizationUpdate(JSONDeSerializableAllowEmpty, josepy.JSONObjectWithFields):
    """Message type that allows (de-)serialization of authorization update request payloads.

    Inherits from :class:`JSONDeSerializableAllowEmpty` so that POST-as-GET requests don't result in a parsing error.
    """

    status: AuthorizationStatus = josepy.Field(
        "status", decoder=AuthorizationStatus, omitempty=True
    )
    """The authorization's new status."""


class AccountUpdate(JSONDeSerializableAllowEmpty, acme.messages.Registration):
    """Patched :class:`acme.messages.Registration` message type that adds a *status* field for status update requests.

    Inherits from :class:`JSONDeSerializableAllowEmpty` so that POST-as-GET requests don't result in a parsing error.
    """

    status: AccountStatus = josepy.Field(
        "status", decoder=AccountStatus, omitempty=True
    )
    """The account's new status."""


class NewOrder(josepy.JSONObjectWithFields):
    """Message type for new order requests."""

    identifiers: typing.List[typing.Dict[str, str]] = josepy.Field(
        "identifiers", omitempty=True
    )
    """The requested identifiers."""
    not_before: "datetime.datetime" = acme.messages.fields.RFC3339Field(
        "notBefore", omitempty=True
    )
    """The requested *notBefore* field in the certificate."""
    not_after: "datetime.datetime" = acme.messages.fields.RFC3339Field(
        "notAfter", omitempty=True
    )
    """The requested *notAfter* field in the certificate."""

    @classmethod
    def from_data(
        cls,
        identifiers: typing.Union[
            typing.List[typing.Dict[str, str]], typing.List[str]
        ] = None,
        not_before: "datetime.datetime" = None,
        not_after: "datetime.datetime" = None,
    ) -> "NewOrder":
        """Class factory that takes care of parsing the list of *identifiers*.

        :param identifiers: Either a :class:`list` of :class:`dict` where each dict consists of the keys *type* \
            and *value*, or a :class:`list` of :class:`str` that represent the DNS names.
        :param not_before: The requested *notBefore* field in the certificate.
        :param not_after: The requested *notAfter* field in the certificate.
        :return: The new order object.
        """
        kwargs = {}

        if type(identifiers[0]) is dict:
            kwargs["identifiers"] = identifiers
        elif type(identifiers[0]) is str:
            kwargs["identifiers"] = [
                dict(type="dns", value=identifier) for identifier in identifiers
            ]
        else:
            raise ValueError(
                "Could not decode identifiers list. Must be either List(str) or List(dict) where "
                "the dict has two keys 'type' and 'value'"
            )

        kwargs["not_before"] = not_before
        kwargs["not_after"] = not_after

        return cls(**kwargs)


class Account(josepy.JSONObjectWithFields):
    """Patched :class:`acme.messages.Registration` message type that adds a *kid* field.

    This is the representation of a user account that the :class:`~acmetk.client.AcmeClient` uses internally.
    The :attr:`kid` field is sent to the remote server with every request and used for request verification.
    Fields that see no use inside the client have been removed.
    """

    status: AccountStatus = josepy.Field("status", omitempty=True)
    """The account's status."""
    contact: typing.Tuple[str] = josepy.Field("contact", omitempty=True)
    """The account's contact info."""
    orders: str = josepy.Field("orders", omitempty=True)
    """URL of the account's orders list."""
    kid: str = josepy.Field("kid")
    """The account's key ID."""


class Order(acme.messages.Order):
    """Patched :class:`acme.messages.Order` message type that adds a *URL* field.

    The *URL* field is populated by copying the *Location* header from responses in the
    :class:`~acmetk.client.AcmeClient`.
    This field is used by the :class:`~acmetk.server.AcmeProxy` to store the *proxied* URL and to be able
    to map an internal order to that of the remote CA.
    """

    url: str = josepy.Field("url", omitempty=True)
    """The order's URL at the remote CA."""


class KeyChange(josepy.JSONObjectWithFields):
    account = josepy.Field("account")
    oldKey = josepy.Field("oldKey", decoder=josepy.jwk.JWK.from_json)


class SignedKeyChange(josepy.JSONObjectWithFields):
    protected = josepy.Field("protected")
    payload = josepy.Field("payload")
    signature = josepy.Field("signature")

    @classmethod
    def from_data(cls, kc, key, alg, **kwargs):
        data = acme.jws.JWS.sign(
            kc.json_dumps().encode(), key=key, alg=alg, nonce=None, **kwargs
        )

        signature = josepy.b64.b64encode(data.signature.signature).decode()
        payload = josepy.b64.b64encode(data.payload).decode()
        protected = josepy.b64.b64encode(data.signature.protected.encode()).decode()
        return cls(protected=protected, payload=payload, signature=signature)
