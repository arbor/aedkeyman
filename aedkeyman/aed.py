#
# Copyright (c) 2019 NETSCOUT Systems, Inc.
# All rights reserved.  Proprietary and confidential.
#

"""
Manage a connection and interface with Arbor Edge Defense to manage keys on
the HSM.
"""

import requests
from requests.exceptions import ConnectionError
import logging


class ArborEdgeDefenseException(Exception):
    """
    General error from ArborEdge.
    """
    pass


class ArborEdgeDefense(object):
    """
    Manage Keys on AED.
    """
    def __init__(self, hostname, token, hsm_user, hsm_pass,
                 disable_cert_verify=False):
        self.token = token
        self.hsm_user = hsm_user
        self.hsm_pass = hsm_pass
        self.baseurl = 'https://%s/api/aps/v2' % (hostname,)
        self.verify = not disable_cert_verify

    def import_key(self, name, priv, cert=None):
        body = {
            'label': name,
            'privateKey': priv,
            'certificate': cert,
        }
        res = self._request('POST', "/hsm/certificates/",
                            body)

        if res.status_code != 201:
            self._raise_errors(res)

    def delete_key(self, name):
        res = self._request('DELETE', "/hsm/certificates/" + name)
        if res.status_code != 204:
            self._raise_errors(res)

    def list_keys(self):
        res = self._request('GET', "/hsm/certificates/", data={'details': 1})
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
                'type': item['type']
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
        """
        Request helper. This issues a request and does not handle
        authentication.
        """
        logging.debug("%s %s\n%s" % (method, self.baseurl + url_suffix, data))
        headers = {
            'X-Arbux-APIToken': self.token,
            'X-Arbux-HSMUsername': self.hsm_user,
            'X-Arbux-HSMPassword': self.hsm_pass,
        }

        try:
            if method == 'POST':
                result = requests.post(url=self.baseurl + url_suffix,
                                       headers=headers,
                                       json=data,
                                       verify=self.verify)
            elif method == 'GET':
                result = requests.get(url=self.baseurl + url_suffix,
                                      headers=headers, params=data,
                                      verify=self.verify)
            elif method == 'DELETE':
                result = requests.delete(url=self.baseurl + url_suffix,
                                         headers=headers, verify=self.verify)
        except ConnectionError, exc:
            # TODO: should clean this up
            raise ArborEdgeDefenseException(str(exc))
        else:
            logging.debug("%d\n%s" % (result.status_code, result.text))
            if result.status_code == 503:
                msg = 'Service Unavailable. Try starting services on AED.'
                raise ArborEdgeDefenseException(msg)

        return result
