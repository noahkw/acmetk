API
===

ACME Client
###########


.. autoclass:: acmetk.client.AcmeClient
    :class-doc-from: class
    :exclude-members: Config
    :members:

.. autopydantic_settings:: acmetk.client.AcmeClient.Config
   :settings-show-json: False
   :settings-show-config-member: False
   :settings-show-config-summary: False
   :settings-show-validator-members: False
   :settings-show-validator-summary: False
   :field-list-validators: False

Challenge Solvers & Configurations
----------------------------------

.. automodule:: acmetk.client.challenge_solver
    :members:

Exceptions
----------

.. automodule:: acmetk.client.exceptions
    :members:

External Account Binding Credentials
------------------------------------

.. autoclass:: acmetk.client.client.ExternalAccountBindingCredentials
    :members:
    :inherited-members:

ACME Servers
############

ACME Server Base
----------------

.. autoclass:: acmetk.server.AcmeServerBase
    :members:
    :exclude-members: Config
    :inherited-members:

ACME Relay Base
---------------

.. autoclass:: acmetk.server.AcmeRelayBase
    :members:
    :exclude-members: Config
    :show-inheritance:

ACME Certificate Authority
--------------------------

.. autoclass:: acmetk.server.AcmeCA
    :members:
    :exclude-members: Config
    :show-inheritance:

ACME Broker
-----------

.. autoclass:: acmetk.server.AcmeBroker
    :members:
    :exclude-members: Config
    :show-inheritance:

ACME Proxy
----------

.. autoclass:: acmetk.server.AcmeProxy
    :members:
    :exclude-members: Config
    :show-inheritance:

Challenge Validators
--------------------

.. automodule:: acmetk.server.challenge_validator
    :members:
    :inherited-members:

External Account Binding
------------------------

.. autoclass:: acmetk.server.external_account_binding.ExternalAccountBinding
    :members:

.. autoclass:: acmetk.server.external_account_binding.ExternalAccountBindingStore
    :members:

.. autoclass:: acmetk.server.external_account_binding.AcmeEABMixin
    :members:

Plugin Registry
---------------

.. autoclass:: acmetk.plugin_base.PluginRegistry
    :members:

Models
######

Message types
-------------

.. automodule:: acmetk.models.messages
    :members:
    :show-inheritance:

Database models
---------------

Account
^^^^^^^
.. autoclass:: acmetk.models.account.Account
    :members:

Authorization
^^^^^^^^^^^^^
.. autoclass:: acmetk.models.authorization.Authorization
    :members:

Certificate
^^^^^^^^^^^
.. autoclass:: acmetk.models.certificate.Certificate
    :members:

Challenge
^^^^^^^^^
.. autoclass:: acmetk.models.challenge.Challenge
    :members:

.. autoclass:: acmetk.models.challenge.ChallengeType
    :members:

Identifier
^^^^^^^^^^
.. automodule:: acmetk.models.identifier
    :members:

Order
^^^^^
.. autoclass:: acmetk.models.order.Order
    :members:

Utils
#####
.. automodule:: acmetk.util
    :members:
