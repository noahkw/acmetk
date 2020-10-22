import uuid


def generate_nonce():
    return uuid.uuid4().hex
