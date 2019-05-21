# Copyright (c) 2019 NETSCOUT Systems, Inc.

"""Manage keys on Arbor Edge Defense."""

import logging
import pprint
from builtins import object
from builtins import str

import requests
from requests.exceptions import ConnectionError


class ArborEdgeDefenseException(Exception):
    """General error from ArborEdge."""

    pass


class ArborEdgeDefense(object):
    """Manage Keys on AED."""

    def __init__(self, hostname, token, creds, use_hsm=False,
                 disable_cert_verify=False):
        """
        Initialize an instance.

        hsm_user -- crypto user name
        hsm_user -- crypto user password
        token -- API token
        use_hsm -- True if using an HSM vs newer Crypto Accelerator Module
        disable_cert_verify -- disable verification AED cert (LAB USE)
        """
        self.token = token
        self.creds = creds
        self.baseurl = 'https://%s/api/aps/v2' % (hostname,)
        self.verify = not disable_cert_verify

        # path to the certificate API end-points
        self.use_hsm = use_hsm
        if use_hsm:
            self.certpath = '/hsm/certificates/'
        else:
            self.certpath = '/crypto/certificates/'

    def import_key(self, name, priv, cert=None):
        """Import a key."""
        body = {
            'label': name,
            'privateKey': priv,
            'certificate': cert,
        }
        res = self._request('POST', self.certpath, body)

        if res.status_code != 201:
            self._raise_errors(res)

    def delete_key(self, name):
        """Delete a key."""
        res = self._request('DELETE', self.certpath + name)
        if res.status_code != 204:
            self._raise_errors(res)

    def list_keys(self):
        """List keys."""
        res = self._request('GET', self.certpath, data={'details': 1})
        if res.status_code != 200:
            self._raise_errors(res)

        keys = []
        for item in res.json():
            # In some versions there can be a trailing empty dict. This has
            # been fixed in 6.0.
            if 'label' not in item:
                continue

            key = {
                'name': item['label'],
                'type': item['type'],
            }
            if 'public' in item:
                key['public'] = item['public']
            keys.append(key)

        return keys

    def _raise_errors(self, res):
        msgs = []
        for err in res.json()['errors']:
            msgs.append("%s: %s" % (err['code'], err['message']))

        raise ArborEdgeDefenseException('\n'.join(msgs))

    def _request(self, method, url_suffix, data=None):
        """Issue a request."""
        headers = {
            'X-Arbux-APIToken': self.token,
        }

        if self.use_hsm:
            headers['X-Arbux-HSMUsername'] = self.creds['hsm_user']
            headers['X-Arbux-HSMPassword'] = self.creds['hsm_pass']
        else:
            headers['X-Arbux-KeystorePass'] = self.creds['keystore_pass']

        url = self.baseurl + url_suffix
        logging.debug("%s %s" % (method, url))
        logging.debug("HEADERS: %s" % pprint.pformat(headers))
        logging.debug("BODY: %s" % data)

        try:
            if method == 'POST':
                result = requests.post(url=url,
                                       headers=headers,
                                       json=data,
                                       verify=self.verify)
            elif method == 'GET':
                result = requests.get(url=url,
                                      headers=headers, params=data,
                                      verify=self.verify)
            elif method == 'DELETE':
                result = requests.delete(url=url,
                                         headers=headers, verify=self.verify)
        except ConnectionError as exc:
            # TODO: should clean this up
            raise ArborEdgeDefenseException(str(exc))
        else:
            logging.debug("%d\n%s" % (result.status_code, result.text))
            if result.status_code == 503:
                msg = 'Service Unavailable. Try starting services on AED.'
                raise ArborEdgeDefenseException(msg)

        return result
