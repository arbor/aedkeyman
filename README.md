aedkeyman
=====

NETSCOUT Arbor Edge Defense (AED) protects networks from malicious traffic and
DDOS attacks. When the appliance is equipped with an HSM it decrypts TLS
streams to detect and block encrypted layer 7 attacks. See the [press
release](https://www.netscout.com/aed-solution-press-release) for more info.

aedkeyman facilitates this by providing commands to manage keys on AED and
between it and third-party cryptography services providing key mangement such
as [SmartKey](https://www.smartkey.io/).


Usage
=====

aedkeyman supports importing, listing, and deleting keys from AED, as well as
the ability to synchronize keys with Equinix SmartKey.

Install using setuptools:

```
    python setup.py install
```

Invoke the script:

```
    aedkeyman --help
```

To enable communication with the AED some configuration must be provided. This
is currently done with environment variables:

1. Generate an API token from the AED CLI if that has not already been done.

    To list existing tokens:

    ```
    services aaa local apitoken show
    ```

    To generate one for the *admin* user:

    ```
    services aaa local apitoken generate admin
    ```

2. Set *AED_HOST* to the host name and *AED_TOKEN* to the API token created
    in the previous step:

    ```
    export AED_HOST=example.localdomain
    export AED_TOKEN=cOiEeOPFkKtLgPRagMbHd36ciDu7P2tWM_NqID6v
    ```

3. Set the HSM credentials with *AED_HSM_USER* and *AED_HSM_PASS* to authorize
    the API user to access the HSM:

    ```
    export AED_HSM_USER=examplecu
    export AED_HSM_PASS=examplepass
    ```

4. Run the command to list keys on AED to verify communication with AED:

    ```
    ./aedkeyman.py aed-list-keys
    ```

SmartKey
========

Equinix SmartKey is a cloud based key management and cryptography service.

The SmartKey service can be used with popular servers such as Apache, NGINX,
and others, both commercial and open source. This is done by configuring them
to use SmartKey's PKCS engine. [The SmartKey
Dashboard](https://www.smartkey.io/) and/or [OpenSC
Tools](https://github.com/OpenSC/OpenSC) are used to manage keys in SmartKey.

aedkeyman enables AED to protect a web server using SmartKey by keeping a copy
of the keys in SmartKey on the HSM in AED. When the AED HSM has the same keys
as the web server,  AED will decrypt the streams and inspect them for attacks.

To use SmartKey with AED, first use the SmartKey Dashboard
(https://www.smartkey.io/) to manage the keys and certificates used by your
webserver. Be sure to set the *EXPORTABLE* flag for each so aedkeyman has
permission to export it.

This requires signing up for the SmartKey service and configuring your
webserver to use it.

There are examples of this in the [Knowledge
Base](https://support.smartkey.io/). We suggest configuring the webserver to
use the SmartKey PKCS engine to access the security objects in the SmartKey
HSM. You may need to use additional open source tools to export or import keys
to a third party for signing - consult the Knowledge Base at
[https://support.smartkey.io/](https://support.smartkey.io/).

Example Usage
-------------

1. First create a session with the SmartKey service by authenticating:

    ```
    /aedkeyman.py skey-login --username=exampleuser \
        --account-id=8a1df675-7807-4b7e-9446-19b607518fa4
    ```

    You will be prompted for a password. Upon successfully logging in a message
    will be displayed:

    ```
    Session will expire in 0:15:00. Use the 'skey-logout' command to terminate
    it sooner.
    ```

2. The command to list keys can be run to show which keys are present or
    missing.

    ```
    ./aedkeyman.py skey-list-keys --unified
    ```

3. Synchronize the keys from the SmartKey HSM to the HSM on the AED appliance.

    ```
    ./aedkeyman.py skey-sync-keys
    ```

4. Close the session:

    ```
    ./aedkeyman.py skey-logout
    ```
