#
# Copyright (c) 2019 NETSCOUT Systems, Inc.
# All rights reserved.  Proprietary and confidential.
#
"""
Manage a connection and interface with Equinix Smart Key to manage keys.
"""

import os
import stat
import base64
import requests
import json
import logging
import pprint

APP_TOKEN_FILE = os.path.join(os.environ['HOME'], '.skey_app_token')
USER_TOKEN_FILE = os.path.join(os.environ['HOME'], '.skey_user_token')


class SmartKeyException(Exception):
    """
    General error from SmartKey
    """
    pass


class SmartKeyNeedsAuthException(SmartKeyException):
    """
    Authorization failed due to missing credentials.
    """
    pass


class SmartKeyNeedsAcctSelectException(SmartKeyException):
    """
    Account selection must be performed.
    """
    pass


class SmartKeyAuthAppException(SmartKeyException):
    """
    Raise when application authentication fails.
    """
    pass


class SmartKeyAuthUserException(SmartKeyException):
    """
    Raise when user authentication fails.
    """
    pass


class SmartKey(object):
    """
    Manage a connection and interface with SmartKey using the REST API.
    """
    def __init__(self, apikey=None):
        """
        Initialize an instance. This will fetch the token from disk
        automatically if it exists. Pass an API key to authenticate as
        an application.

        apikey - API key for SmartKey
        """
        self.baseurl = 'https://www.smartkey.io'
        self.token = None
        self.token_file = USER_TOKEN_FILE if apikey is None else APP_TOKEN_FILE
        self.apikey = apikey
        self._fetch_token()

    def generate_rsa_key(self, name, size, description, group_id=None):
        """
        Generate an RSA key with the given parameters.
        """
        body = {
            'obj_type': 'RSA',
            'name': name,
            'description': description,
            # [ AES, DES, DES3, RSA, EC, OPAQUE, HMAC, SECRET, CERTIFICATE ]
            'rsa': {
                'key_size': size
            },

            # Impose no constraints on encryption or key wrapping
            'encryption_policy': [{}],

            # Permit EXPORT of the key to sync with the Arbor HSM and
            # the web server. Permit APPMANAGEABLE so we can delete,
            # and SIGN if we want to use it to sign other keys.
            'key_ops': ['EXPORT', 'APPMANAGEABLE', 'SIGN'],
        }

        if group_id is not None:
            body['group_id'] = group_id

        res = self._request('POST', "/crypto/v1/keys",
                            data=json.dumps(body))
        if res.status_code != requests.codes.created:
            # How can we determine why the generation failed? name already
            # exists for example.
            msg = "Cannot generate key: %d %s" % (res.status_code, res.text)
            raise SmartKeyException(msg)

        kid = res.json()['kid']
        return kid

    def generate_ec_key(self, name, curve, group_id, description):
        """
        Generate an Elliptic Curve key with the given parameters.
        """
        body = {
            'obj_type': 'EC',
            'name': name,
            'elliptic_curve': curve,
            'description': description,
            'encryption_policy': [{}],
            'key_ops': ['EXPORT', 'APPMANAGEABLE'],
        }

        if group_id is not None:
            body['group_id'] = group_id

        res = self._request('POST', "/crypto/v1/keys",
                            data=json.dumps(body))
        if res.status_code != requests.codes.created:
            # How can we determine why the generation failed? name already
            # exists for example.
            msg = "Cannot generate key: %d %s" % (res.status_code, res.text)
            raise SmartKeyException(msg)

        kid = res.json()['kid']
        return kid

    def delete_key(self, kid):
        """
        Delete a key.
        """
        res = self._request('DELETE',
                            "/crypto/v1/keys/" + kid)
        if res.status_code != requests.codes.no_content:
            msg = "Cannot delete key: %d %s" % (res.status_code, res.text)
            raise SmartKeyException(msg)

    def list_keys(self, name=None, group_id=None):
        """
        TODO: group_id
        """
        data = None
        if name is not None:
            data = {'name': name}

        res = self._request('GET', "/crypto/v1/keys", data=data)
        if res.status_code != requests.codes.ok:
            msg = "%d %s" % (res.status_code, res.text)
            raise SmartKeyException(msg)

        data = []
        keys = res.json()

        return keys

    def list_accounts(self):
        """
        List the accounts.
        """
        res = self._request('GET', "/sys/v1/accounts")
        if res.status_code != requests.codes.ok:
            msg = "%d %s" % (res.status_code, res.text)
            raise SmartKeyException(msg)

        return res.json()

    def list_groups(self):
        """
        List the groups.
        """
        res = self._request('GET', "/sys/v1/groups")
        if res.status_code != requests.codes.ok:
            msg = "%d %s" % (res.status_code, res.text)
            raise SmartKeyException(msg)

        return res.json()

    def get_key(self, kid):
        """
        Get a specific key (security object) by key id.
        """
        res = self._request('GET', "/crypto/v1/keys/%s" % kid)
        if res.status_code != requests.codes.ok:
            msg = "%d %s" % (res.status_code, res.text)
            raise SmartKeyException(msg)

        return res.json()

    def export_key(self, kid):
        """
        Export the key data.
        """
        body = {
            'kid': kid
        }
        res = self._request('POST',
                            "/crypto/v1/keys/export",
                            json.dumps(body))

        if res.status_code != requests.codes.ok:
            msg = "%d %s" % (res.status_code, res.text)
            raise SmartKeyException(msg)

        data = res.json()
        logging.debug(pprint.pformat(data))

        return data

    def auth_app(self, save=True):
        """
        Authenticate and acquire bearer token to use for subsequent requests.
        """
        logging.info("Authenticating with SmartKey as an application")
        headers = {
            'Authorization': 'Basic ' + self.apikey
        }
        res = requests.request(method='POST',
                               url="%s/sys/v1/session/auth" % (self.baseurl,),
                               headers=headers)
        if res.status_code != requests.codes.ok:
            fmt = "Application authentication failed %d: %s"
            raise SmartKeyAuthAppException(fmt % (res.status_code,
                                                  res.text))
        else:
            logging.info("Successfully logged in to SmartKey")

            decoded = json.loads(res.text)
            logging.debug(pprint.pformat(decoded))
            self.token = decoded['access_token']

        # Application will always save the token
        self._save_token()

    def auth_user(self, username, password, save=False):
        """
        Authenticate and acquire bearer token to use for subsequent requests.
        """
        logging.info("Authenticating with SmartKey as a user")
        encoded = base64.b64encode('%s:%s' % (username, password))
        headers = {
            'Authorization': 'Basic ' + encoded
        }
        res = requests.request(method='POST',
                               url="%s/sys/v1/session/auth" % (self.baseurl,),
                               headers=headers)
        if res.status_code != requests.codes.ok:
            fmt = "Authentication failed %d: %s"
            raise SmartKeyAuthUserException(fmt % (res.status_code,
                                                   res.text))
        else:
            logging.info("Successfully logged in to SmartKey")

            decoded = json.loads(res.text)
            logging.debug(pprint.pformat(decoded))
            self.token = decoded['access_token']
            expires = decoded['expires_in']

        if save:
            self._save_token()

        return expires

    def select_account(self, acct_id):
        """
        """
        body = {
            'acct_id': acct_id
        }
        res = self._request('POST',
                            "/sys/v1/session/select_account",
                            json.dumps(body))

        if res.status_code != requests.codes.ok:
            msg = "%d %s" % (res.status_code, res.text)
            raise SmartKeyException(msg)

        data = res.json()
        logging.debug(pprint.pformat(data))
        return data

    def terminate_session(self):
        """
        """
        if self.token is None:
            raise SmartKeyException("No saved session token to invalidate.")

        res = self._request('POST', "/sys/v1/session/terminate")
        if res.status_code == 204:
            self.purge_token()
        else:
            msg = "%d %s" % (res.status_code, res.text)
            raise SmartKeyException(msg)

    def _save_token(self):
        """
        Save the auth token to disk to use it in the future.
        """
        # TODO: use NamedTemporaryFile() and move in to place
        with open(self.token_file, "w") as tfile:
            tfile.write(self.token)

        os.chmod(self.token_file, stat.S_IRUSR | stat.S_IWUSR)

    def _fetch_token(self):
        """
        Return saved auth token or fetch a new one.
        """
        try:
            with open(self.token_file) as tfile:
                self.token = tfile.readline().rstrip()
                fmt = "Loaded bearer token %s from %s"
                logging.info(fmt % (self.token, self.token_file))
        except IOError:
            if self.apikey is not None:
                logging.info("No token file on disk. Acquiring.")
                self.auth_app()

    def purge_token(self):
        """
        Remove the saved auth token
        """
        self.token = None
        os.unlink(self.token_file)

    def _request_aux(self, method, url_suffix, data):
        """
        Request helper. This issues a request and does not handle
        authentication.
        """
        logging.debug("%s %s\n%s" % (method, self.baseurl + url_suffix, data))

        headers = {
            'Authorization': 'Bearer ' + self.token
        }

        if method == 'POST':
            result = requests.post(self.baseurl + url_suffix,
                                   headers=headers,
                                   data=data)
        elif method == 'GET':
            result = requests.get(url=self.baseurl + url_suffix,
                                  headers=headers, params=data)
        elif method == 'DELETE':
            result = requests.delete(url=self.baseurl + url_suffix,
                                     headers=headers)

        logging.debug("%d\n%s" % (result.status_code, result.text))

        return result

    def _request(self, method, url_suffix, data=None):
        """
        Make a request and if it fails due to authorization, automatically
        authenticate and try again.
        """
        # No token means we need to authenticate and get one
        if self.token is None:
            logging.debug("No token; need authentication")
            if self.apikey is None:
                msg = "SmartKey authentication required"
                raise SmartKeyNeedsAuthException(msg)
            else:
                self.auth_app()

        result = self._request_aux(method, url_suffix, data)
        if result.status_code not in [200, 201, 204]:
            # If we're doing application authentication retry automatically.
            # 403 can mean 'Requested operation is not allowed with this key'
            # in which case (re)authenticating won't solve the problem so we're
            # checking the text to see if it's this specific error.
            if (result.status_code == 403 and
                    'Requested operation is not allowed' not in result.text):
                if self.apikey is not None:
                    logging.info("Response has 403: %s (Retrying...)" %
                                 (result.text,))
                    self.auth_app()
                    result = self._request_aux(method, url_suffix, data)
                else:
                    raise SmartKeyNeedsAuthException(result.text)
            elif (result.status_code == 401 and
                    ('operation requires an account to be selected' in
                     result.text)):
                raise SmartKeyNeedsAcctSelectException(result.text)
            else:
                # Note that indicating there was an error here is purely a
                # debug message. It's normal for a client to issue requests
                # that don't work out (i.e. key doesn't exist) and we don't
                # want to report that as an error in the log here.
                logging.debug("Response has error: %s %s" %
                              (result.status_code, result.text))

        return result
