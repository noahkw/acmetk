import json

import OpenSSL
import acme
import cryptography
import josepy
from acme.messages import ResourceBody
from cryptography import x509

from acme_broker import models

ERROR_CODE_STATUS = {
    "unauthorized": 401,
    "orderNotReady": 403,
    "accountDoesNotExist": 404,
}


def get_status(error_code):
    return ERROR_CODE_STATUS.get(error_code, 400)


def decode_cert(b64der):
    return x509.load_der_x509_certificate(josepy.json_util.decode_b64jose(b64der))


def encode_cert(cert):
    return josepy.encode_b64jose(
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
    )


class Revocation(josepy.JSONObjectWithFields):
    """Revocation message.

    :ivar .ComparableX509 certificate: `OpenSSL.crypto.X509` wrapped in
        `.ComparableX509`

    """

    certificate = josepy.Field("certificate", decoder=decode_cert, encoder=encode_cert)
    reason = josepy.Field("reason")


def encode_csr(csr):
    """Encode CSR as JOSE Base-64 DER."""
    return josepy.encode_b64jose(
        csr.public_bytes(
            encoding=cryptography.hazmat.primitives.serialization.Encoding.DER
        )
    )


def decode_csr(b64der):
    return cryptography.x509.load_der_x509_csr(josepy.json_util.decode_b64jose(b64der))


class CertificateRequest(josepy.JSONObjectWithFields):
    csr = josepy.Field("csr", decoder=decode_csr, encoder=encode_csr)


class JSONDeSerializableAllowEmpty:
    @classmethod
    def json_loads(cls, json_string):
        """Deserialize from JSON document string."""
        try:
            if len(json_string) == 0:
                loads = "{}"
            else:
                loads = json.loads(json_string)
        except ValueError as error:
            raise josepy.errors.DeserializationError(error)
        return cls.from_json(loads)


class AuthorizationUpdate(JSONDeSerializableAllowEmpty, josepy.JSONObjectWithFields):
    status = josepy.Field("status", decoder=models.AuthorizationStatus, omitempty=True)


class AccountUpdate(JSONDeSerializableAllowEmpty, acme.messages.Registration):
    status = josepy.Field("status", decoder=models.AccountStatus, omitempty=True)


class NewOrder(ResourceBody):
    """New Order Resource Body."""

    identifiers = josepy.Field("identifiers", omitempty=True)
    not_before = josepy.Field("notBefore", omitempty=True)
    not_after = josepy.Field("notAfter", omitempty=True)

    @classmethod
    def from_data(cls, identifiers=None, not_before=None, not_after=None, **kwargs):
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


class Account(ResourceBody):
    """Account Resource Body."""

    status = josepy.Field("status", omitempty=True)
    contact = josepy.Field("contact", omitempty=True)
    orders = josepy.Field("orders", omitempty=True)
    kid = josepy.Field("kid")


class Order(ResourceBody):
    """Order Resource Body.

    Patched version of the acme module's order.
    Allows storing the order's url."""

    url = josepy.Field("url", omitempty=True)
    identifiers = josepy.Field("identifiers", omitempty=True)
    status = josepy.Field(
        "status", decoder=acme.messages.Status.from_json, omitempty=True
    )
    authorizations = josepy.Field("authorizations", omitempty=True)
    certificate = josepy.Field("certificate", omitempty=True)
    finalize = josepy.Field("finalize", omitempty=True)
    expires = acme.messages.fields.RFC3339Field("expires", omitempty=True)
    error = josepy.Field("error", omitempty=True, decoder=acme.messages.Error.from_json)

    @identifiers.decoder
    def identifiers(
        value,
    ):  # pylint: disable=no-self-argument,missing-function-docstring
        return tuple(
            acme.messages.Identifier.from_json(identifier) for identifier in value
        )
