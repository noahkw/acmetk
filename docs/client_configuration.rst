Client Configuration
====================

Setting the directory
#####################

.. _config_clients:

When the ACME server is up and running, the clients need to be pointed to its directory URL.
This is achieved in different ways depending on the client and should be part of its documentation.
The following clients were tested against and are thus described here.

*
   `Acmetiny <https://github.com/diafygi/acme-tiny>`_: Simply set the argument :code:`--directory-url` when running the
   client:

   .. code-block:: bash

      acme-tiny --directory-url https://my-server.com/directory

*
   `Certbot <https://github.com/certbot/certbot>`_: Set the server option in the :code:`certbot.ini` and optionally
   set the config directory to avoid confusion as it is set to :code:`/etc/letsencrypt` by default.

   :code:`certbot.ini`:

   .. code-block:: ini

      server = https://my-server.com/directory
      config-dir = /etc/my_server_acme

*
   :class:`~acme_broker.client.AcmeClient`: Pass the directory URL when initializing the client object.

   .. code-block:: python

      from acme_broker.client import AcmeClient

      client = AcmeClient(
         directory_url="https://my-server.com/directory",
         private_key=...,
         contact=...,
      )

*
   `Dehydrated <https://github.com/dehydrated-io/dehydrated>`_: Set the CA option in the :code:`config` file and specify
   it when running dehydrated.

   :code:`./config`:

   .. code-block:: ini

      CA=https://my-server.com/directory

   .. code-block:: bash

      dehydrated --config ./config

.. _config_clients_eab:

External Account Binding
########################

ACME servers may be configured to require that new account registrations contain an external account binding to prove
that the user has control over some resource outside of the account key itself, see
`7.3.4. External Account Binding <https://tools.ietf.org/html/rfc8555#section-7.3.4>`_.

The mechanism implemented in this package, :class:`~acme_broker.server.external_account_binding.AcmeEAB`,
leverages SSL client certificates to identify a user.
The user loads their SSL client certificate into a browser and visits :code:`https://my-server.com/eab`, copying
the *kid* and *hmac_key* values which are then specified when registering a new account.
The following shows how to pass them to Certbot if the *kid* (equal to the email address in the certificate) is
:code:`certmail@my-server.com` and the *hmac_key* is :code:`L6-GB7Jj-CNNpSAJUgGzZw`:

.. code-block:: bash

    certbot -c certbot.ini register --agree-tos -m certmail@my-server.com \
        --eab-kid certmail@my-server.com \
        --eab-hmac-key L6-GB7Jj-CNNpSAJUgGzZw
