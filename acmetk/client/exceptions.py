import acme.messages


class AcmeClientException(Exception):
    """General ACME client exception."""

    pass


class CouldNotCompleteChallenge(AcmeClientException):
    """Exception that is raised if completion of a specific challenge failed."""

    def __init__(self, challenge, *args):
        super().__init__(*args)
        self.challenge: acme.messages.ChallengeBody = challenge
        """The challenge whose completion was unsuccessful."""

    def __str__(self):
        return f"Could not complete challenge: {self.challenge}"


class PollingException(AcmeClientException):
    """Exception that is used internally to communicate polling timeouts or errors."""

    def __init__(self, obj, *args):
        super().__init__(*args)
        self.obj = obj
