import json

import acme
import cryptography
import josepy
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


class Revocation(josepy.JSONObjectWithFields):
    """Revocation message.

    :ivar .ComparableX509 certificate: `OpenSSL.crypto.X509` wrapped in
        `.ComparableX509`

    """

    certificate = josepy.Field(
        "certificate", decoder=decode_cert, encoder=josepy.encode_cert
    )
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
