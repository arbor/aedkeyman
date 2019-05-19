# Copyright (c) 2019 NETSCOUT Systems, Inc.

"""Test SmartKey connection management and interface."""

import base64
import json
import sys
import unittest


import aedkeyman

import requests


if sys.version_info >= (3, 3):
    from unittest.mock import mock_open, patch, Mock, MagicMock
else:
    from mock import mock_open, patch, Mock, MagicMock

BASE_URL = 'https://www.smartkey.io/'

BEARER_TOKEN = ('25mjpor8S9igwuXhFi8UuWqb-O54cO1cZVG5r_BRIryMF7JUu7oXdV5ImI'
                + 'F88UyEkURTEKp7Xi-c9dO2gC7r4w')

API_KEY = ('ZmYxNmQzZTctNDgxMS00OTNmLWE1MDEtOWUxZDFlYzkzYjljOmVIamhBUU'
           + '1Xd3NzcFBDMTNDZ3hUVEdhQTNZeEhabzVvcFl2UVRkM1FjRFJHRzJEQXVO'
           + 'YWlJSXFrU21yTTNuTjZaeU90UDlMQnc1aWs4NjhtdTRTcm5B')

test_rsa_pub = ('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAslLVLpYIGaPN23'
                + 'n7JGXwPwR4U1qRBXnoTOEGYH2EDmQ8YXIjylhlYUSr2mPmQT8g2JLYerp0'
                + '6fE74B3EIsk4nQkKKgWfyc6/SLKzy2ARTD3HmsFln2Y/Dz/QaeD8AXGfZV'
                + 'rq+EJuud6EjaXLclMmudLl8iPMA70+FqV07fouvpxjNS5HWT01nTjz7pG0'
                + 'pbb5pS1np35BrqnemUGLuD7yyg0Ai6SGyRqn1FrkeLJM2+SLCqwDxP8zKy'
                + 'RfQVfGUFKEpzRLJ6FoFALEXcljLRwDtMbc3WII2y9Qd+R3teucaXSyakAB'
                + 'CsKc0g0NFjeohsq2wD+nTmxLYQwiOd9q6yWtnQIDAQAB')

test_rsa_priv = ('MIIEowIBAAKCAQEAslLVLpYIGaPN23n7JGXwPwR4U1qRBXnoTOEGYH2EDm'
                 + 'Q8YXIjylhlYUSr2mPmQT8g2JLYerp06fE74B3EIsk4nQkKKgWfyc6/SLKz'
                 + 'y2ARTD3HmsFln2Y/Dz/QaeD8AXGfZVrq+EJuud6EjaXLclMmudLl8iPMA7'
                 + '0+FqV07fouvpxjNS5HWT01nTjz7pG0pbb5pS1np35BrqnemUGLuD7yyg0A'
                 + 'i6SGyRqn1FrkeLJM2+SLCqwDxP8zKyRfQVfGUFKEpzRLJ6FoFALEXcljLR'
                 + 'wDtMbc3WII2y9Qd+R3teucaXSyakABCsKc0g0NFjeohsq2wD+nTmxLYQwi'
                 + 'Od9q6yWtnQIDAQABAoIBAAR7pnOHSY5YICDUT6RCB3i/bxqiBFMn1gIixm'
                 + '3ZZ0m+VYdEnueOHS8FZ9rzwnzhmPzg2jOMVEvyU4VGR6FGlOyxEWdDi26/'
                 + 'ysQe2/wbqZZUrPE0IKQnJk7cQEF9KrtgOiKKly16bBKyUvua+gL2hLAiFW'
                 + '5RiJDlKnZYHq5XPmLD0c3sTdPQ5NTjAcm+PX7vccYGSvOVGPHVIjIgJQ7A'
                 + '36DRIS1kWFgkfJCKiO16xWJnM8e5ixnBq9szHTjQfzE9f+GJRWY+j9H6Y4'
                 + 'BENiJo6NtgIglUuruSwmR1RK97304PtNUNClAOn7vix79wfx0VwD7WA/B/'
                 + 'HP61pCTO05USjGECgYEA37EC3iT42L/sOBV+yFAMasOYyEuVu8h5NCLPfE'
                 + 'kqhtdZhxf2US3H0U82Pk1h4sk2n79GGHKqXilUpouyulwI2o7q6czZu6Lr'
                 + '8VxI70lLquLrYvREqW5dtyrv5cLXM53Q31JLNDD1Ircx24N2479pKVppYa'
                 + '/U9KuBggVZSAQUGX0CgYEAzBRYMutcIDJ1qXYecueM86zbnxtDUzEVZ8cZ'
                 + 'YAbYE0ZR2G/bdzeslsjSOa+7IQ57zojqtHBrcrYEVFvT1zR+hrpFiB6Jqt'
                 + 'R5MgWgCTQMIF9ytmxlCA4T3ELX++RPSsC8WifdEwPk8h7rdjd3+m/LUGyE'
                 + 'QPTOMFhYPbPmjZypHqECgYAZ4QKx7JkVim6rtmDqj8g/+c0NLyFtji3niD'
                 + 'd064oN+5AR/wWyMpexcXaXEqDGefzl0l0rquhm6GUwt2y//rHPh0VKMzbl'
                 + 'bF3bmI+fj10/se0Fj7j52RjifgcvD7GR+SoXDBBDQ364u3T7LmRsyNJDxH'
                 + '/4mz0J6WWcQz4nBMHGiQKBgGZOVKDCKF7jrOSVGFKWDa0inL64VhngY1Cx'
                 + 'GOFwzOVsvR75hFXRjS3R4sGUfQTnU92H+dEXAmZxJN59YkdiQ4Oa4byJQo'
                 + '5nEZKoC0BR3TplXwZgdI2DMSWcRNY78BwTXtj7XvJnY2CVa4jJ6dWcMZpR'
                 + 'rEM79hl6UFIuW4fmX0nBAoGBANU2HMpnh6IcGgf9pZK0vZ7AIYc4zaondA'
                 + 'Pl2Jy8nLoBLqubBcBUUp9hUNd1Tsd1ae7Sqm9qA+TNTiGI0swbMRiDgXB2'
                 + 'pvdezBhfQVFPfvyqfMmFSqnmQtaQWCxNwEwBTjA8eRHRq6EGGZd9WIgdy3'
                 + 'sbxcbt+8hybFKWluWsEjaJ')


ec1_pub = (
    'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXs9dJPiF/EZXL3P0++uj8eJsdrvaFuqt'
    + 'u+i+T+G3gNNfubcC4cUyO309fb4syziK8tud4lkttNuaxL7R471hvjyvovr3xATa'
    + '7v7vCxRk9VOh4UapEbOHrEwHgB5qo/g7'
)

rsa1_pub = (
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4hjFq5eU0qdCNVjGStxY'
    + 'SNEWZgCrkKr7UTEniNOiAZJrXJPzuvFzFc4/DcX7cnj+e9UBNFdPI5P6LinUn5rL'
    + 'qXs7Kpaap9NOFREINOj5giSTroqdNRRTSdbK7ApbXNgwWFr6utSPEMGQfaQ/sjY5'
    + 'Tw421g3Czy009dbeD/pMvEQ9LLaU9TvQ6pW5bpB+75hbcux3vCC+hjqpe4z3qFBP'
    + '0Z3EciNRNfdpIRoSlmqoh263TU8NW1Qfl/fLdhpWBwOIc7fkP2ZQo5ZDjxOJ6pwN'
    + 'nnUd+WgwqPoisnSxl/FT4I12PeobcFfsK8EcjHedVQAh6itMEbZ+88CVA/p8zXBx'
    + 'qQIDAQAB'
)

cert1_val = (
    'MIICsjCCAZoCCQDBmHMNRGq3BTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBB0'
    + 'ZXN0LmV4YW1wbGUuY29tMB4XDTE4MDgyMDE5MTMzMloXDTE5MDgyNTE5MTMzMlow'
    + 'GzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD'
    + 'ggEPADCCAQoCggEBAMXNFu3OWuUH0hIzoEQVOaGp095y77QVWpDKBjwT0r4acaa+'
    + 'Bb8RuFfEcXhbxbCHQERy3bjnMAD9o8WTMV4l584KKzBHDcXWqnqZn8oFXqv31z5T'
    + '65ctgyWhj+zTI0H30OssCpAck7CjH4qAZTq9a9Jd4uQ7BxbH0AYZlDYPAuSfEivs'
    + 'S9gardrPqwtem0XdNodi/28TFqlkwILYNwNFhaD6TEKBIfqUobRowd6ODB976ZK/'
    + 'fGQeVOBf6ZOznBKkS495/K9Mk6Ezx3rXFon97tXJ5HE0wduXJH7hROKOywm00vK7'
    + '2jUV08g+JrzAmRPNO41wxYUdc/aUkgUGab4qEdECAwEAATANBgkqhkiG9w0BAQsF'
    + 'AAOCAQEAcWr3xtaRx0ojLSn5U3HYMnGhc8TEoTQM/dtrcpPQYVA3rZzm63Fuyxgb'
    + 'GrgD5p5Ny0v+kYViXHOHi6oXYZCobXvlX0IUT/iVfzBhvOXRdhEbKl7Yjb9chpCX'
    + 'mtltawyjniplnRDM1TkTovqmWcOySxUEY3fgxdNt6g04iPaW6PXKkzzUIGyFU+mH'
    + 'Y+O3txIC6pJIvgyu+2bwCpVmY3LWnpKDhV86QV7WdR3soW4E3A3A8Z80OfRDxIvV'
    + 'ylo7expsuJcruXn0B4HDUBKqncwtVdb3Qs8pocx12Dp00jtjmwZAYDUAHJaYRZGx'
    + '0TRSnB9Wks5OwbylF7vwQS4CBZot+A=='
)

cert1_pub = (
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxc0W7c5a5QfSEjOgRBU5'
    + 'oanT3nLvtBVakMoGPBPSvhpxpr4FvxG4V8RxeFvFsIdARHLduOcwAP2jxZMxXiXn'
    + 'zgorMEcNxdaqepmfygVeq/fXPlPrly2DJaGP7NMjQffQ6ywKkByTsKMfioBlOr1r'
    + '0l3i5DsHFsfQBhmUNg8C5J8SK+xL2Bqt2s+rC16bRd02h2L/bxMWqWTAgtg3A0WF'
    + 'oPpMQoEh+pShtGjB3o4MH3vpkr98ZB5U4F/pk7OcEqRLj3n8r0yToTPHetcWif3u'
    + '1cnkcTTB25ckfuFE4o7LCbTS8rvaNRXTyD4mvMCZE807jXDFhR1z9pSSBQZpvioR'
    + '0QIDAQAB'
)

list_ec1 = {
    "created_at": "20180822T182130Z",
    "creator": {
        "app": "ff16d3e7-4811-493f-a501-9e1d1ec93b9c"},
    "elliptic_curve": "NistP384",
    "enabled": True,
    "key_ops": [
        "EXPORT",
        "APPMANAGEABLE"],
    "kid": "426a950e-7a8f-43c7-ab7b-532973514955",
    "lastused_at": "19700101T000000Z",
    "name": "firstec",
    "never_exportable": False,
    "obj_type": "EC",
    "origin": "FortanixHSM",
    "pub_key": ec1_pub,
    "public_only": False,
    "acct_id": "bf6ea1a8-4e77-478f-a4e2-2524197614a8",
    "group_id": "8820a695-2476-431a-8aea-8f631624912d",
}

list_rsa1 = {
    "created_at": "20180820T190557Z",
    "creator": {
        "app": "ff16d3e7-4811-493f-a501-9e1d1ec93b9c"},
    "custom_metadata": {
        "pkcs11-id": "%06%A0%93%90%F5%15KS%B4%DCz%1B%00%EC%CD%FE"},
    "enabled": True,
    "key_ops": ["SIGN", "VERIFY", "ENCRYPT", "DECRYPT", "WRAPKEY",
                "UNWRAPKEY", "APPMANAGEABLE"],
    "key_size": 2048,
    "kid": "55373e96-ab9b-4f85-81ea-f0d30f2e2bc6",
    "lastused_at": "19700101T000000Z",
    "name": "example.com-key",
    "never_exportable": True,
    "obj_type": "RSA",
    "origin": "FortanixHSM",
    "pub_key": rsa1_pub,
    "public_only": False,
    "rsa": {
        "key_size": 2048,
        "encryption_policy": [{"padding": None}],
        "signature_policy": [{"padding": None}]},
    "acct_id": "bf6ea1a8-4e77-478f-a4e2-2524197614a8",
    "group_id": "8820a695-2476-431a-8aea-8f631624912d",
}

list_cert1 = {
    "created_at": "20180820T192148Z",
    "creator": {
        "app": "ff16d3e7-4811-493f-a501-9e1d1ec93b9c"},
    "custom_metadata": {
        "pkcs11-id": "%06%A0%93%90%F5%15KS%B4%DCz%1B%00%EC%CD%FE"},
    "enabled": True,
    "key_ops": [
        "EXPORT",
        "APPMANAGEABLE"],
    "key_size": 2048,
    "kid": "c3b6d7fb-477b-45df-83d5-0e497275bd5a",
    "lastused_at": "19700101T000000Z",
    "name": "example.com-cert",
    "never_exportable": False,
    "obj_type": "CERTIFICATE",
    "origin": "External",
    "pub_key": cert1_pub,
    "public_only": True,
    "rsa": {
        "key_size": 2048,
        "encryption_policy": [{"padding": {"OAEP": {"mgf": None}}}],
        "signature_policy": [{"padding": None}]},
    "value": cert1_val,
    "acct_id": "bf6ea1a8-4e77-478f-a4e2-2524197614a8",
    "group_id": "8820a695-2476-431a-8aea-8f631624912d",
}

if sys.version_info.major == 3:
    builtins_name = 'builtins'
else:
    builtins_name = '__builtin__'


class SmartKeyTestCase(unittest.TestCase):
    def setUp(self):
        self.maxDiff = 8000

    @patch('aedkeyman.smartkey.requests.request')
    @patch('%s.open' % builtins_name, new=mock_open(read_data=BEARER_TOKEN))
    def test_00_init_with_apikey_and_tokenfile(self, mrequest):
        skey = aedkeyman.SmartKey(apikey=API_KEY)
        open.assert_called_with(aedkeyman.smartkey.APP_TOKEN_FILE)
        self.assertEqual(skey.token, BEARER_TOKEN)

    @patch('aedkeyman.smartkey.requests.request')
    @patch('%s.open' % builtins_name)
    def test_01_init_with_apikey_no_tokenfile(self, mopen, mrequest):
        mrequest.return_value = Mock()
        mrequest.return_value.status_code = requests.codes.ok
        mrequest.return_value.text = ('{"access_token": "%s"}' % BEARER_TOKEN)
        mopenw = MagicMock()
        # We want open to raise the first time only, for the token read
        mopen.side_effect = (IOError("No such file"), mopenw)
        skey = aedkeyman.SmartKey(apikey=API_KEY)
        self.assertEqual(skey.token, BEARER_TOKEN)
        headers = {
            'Authorization': 'Basic ' + API_KEY,
        }
        mrequest.assert_called_with(headers=headers, method='POST',
                                    url=BASE_URL + 'sys/v1/session/auth')

    @patch('aedkeyman.smartkey.requests.request')
    @patch('%s.open' % builtins_name, new=mock_open(read_data=BEARER_TOKEN))
    def test_02_init_no_apikey_and_tokenfile(self, mrequest):
        skey = aedkeyman.SmartKey()
        open.assert_called_with(aedkeyman.smartkey.USER_TOKEN_FILE)
        self.assertEqual(skey.token, BEARER_TOKEN)

    @patch('%s.open' % builtins_name)
    def test_03_init_no_apikey_no_tokenfile(self, mopen):
        mopenw = MagicMock()
        # We want open to raise the first time only, for the token read
        mopen.side_effect = (IOError("No such file"), mopenw)
        skey = aedkeyman.SmartKey()
        self.assertIsNone(skey.token)

    @patch('aedkeyman.smartkey.requests.request')
    @patch('aedkeyman.smartkey.os.close')
    @patch('aedkeyman.smartkey.os.write')
    @patch('aedkeyman.smartkey.os.open')
    @patch('%s.open' % builtins_name)
    def test_04_user_auth_no_tokenfile_save(self, mopen, mosopen, moswrite,
                                            mosclose, mrequest):
        mrequest.return_value = Mock()
        mrequest.return_value.status_code = requests.codes.ok
        mrequest.return_value.text = (
            '{"access_token": "%s","expires_in": 6000}' % BEARER_TOKEN)

        # We want open to raise the first time only, for the token read
        mopen.side_effect = IOError("No such file")
        mosopen.return_value = 99
        skey = aedkeyman.SmartKey()
        username = 'justin'
        password = 'passw0rd'
        skey.auth_user(username, password, save=True)
        self.assertEqual(skey.token, BEARER_TOKEN)
        creds = '%s:%s' % (username, password)
        encoded = base64.b64encode(creds.encode('ascii'))
        headers = {
            'Authorization': 'Basic ' + encoded.decode('ascii'),
        }
        mrequest.assert_called_with(headers=headers, method='POST',
                                    url=BASE_URL + 'sys/v1/session/auth')
        mopen.assert_called_with(aedkeyman.smartkey.USER_TOKEN_FILE)
        moswrite.assert_called_with(99, BEARER_TOKEN.encode())
        mosclose.assert_called_with(99)

    @patch('aedkeyman.smartkey.requests.request')
    @patch('%s.open' % builtins_name)
    def test_05_user_auth_no_tokenfile_no_save(self, mopen, mrequest):
        mrequest.return_value = Mock()
        mrequest.return_value.status_code = requests.codes.ok
        mrequest.return_value.text = (
            '{"access_token": "%s","expires_in": 6000}' % BEARER_TOKEN)
        mopenw = MagicMock()
        # We want open to raise the first time only, for the token read
        mopen.side_effect = (IOError("No such file"), mopenw)
        skey = aedkeyman.SmartKey()
        username = 'justin'
        password = 'passw0rd'
        skey.auth_user(username, password, save=False)
        self.assertEqual(skey.token, BEARER_TOKEN)
        creds = '%s:%s' % (username, password)
        encoded = base64.b64encode(creds.encode('ascii'))
        headers = {
            'Authorization': 'Basic ' + encoded.decode('ascii'),
        }
        mrequest.assert_called_with(headers=headers, method='POST',
                                    url=BASE_URL + 'sys/v1/session/auth')
        mopen.assert_called_once_with(aedkeyman.smartkey.USER_TOKEN_FILE)

    @patch('aedkeyman.SmartKey.auth_app', new=Mock())
    @patch('aedkeyman.smartkey.requests.post')
    def test_20_gen_rsa_key_success(self, mpost):
        skey = aedkeyman.SmartKey()
        skey.token = BEARER_TOKEN
        headers = {
            'Authorization': 'Bearer ' + BEARER_TOKEN,
        }
        req_data = {
            "obj_type": "RSA",
            "name": "test",
            "description": "description",
            "rsa": {"key_size": 2048},
            "encryption_policy": [{}],
            "key_ops": ["EXPORT", "APPMANAGEABLE", "SIGN"],
        }
        resp_data = {
            "created_at": "20180809T152604Z",
            "creator": {"app": "ff16d3e7-4811-493f-a501-9e1d1ec93b9c"},
            "description": "description",
            "enabled": True,
            "key_ops": ["EXPORT", "APPMANAGEABLE", "SIGN"],
            "key_size": 2048,
            "kid": "fe0b726f-ae25-4939-a67b-382a4e7f35f7",
            "lastused_at": "19700101T000000Z",
            "name": "test",
            "never_exportable": False,
            "obj_type": "RSA",
            "origin": "FortanixHSM",
            "pub_key": test_rsa_pub,
            "public_only": False,
            "rsa": {
                "key_size": 2048,
                "encryption_policy": [{"padding": {"OAEP": {"mgf": None}}}],
                "signature_policy": [{"padding": None}],
            },
            "acct_id": "bf6ea1a8-4e77-478f-a4e2-2524197614a8",
            "group_id": "8820a695-2476-431a-8aea-8f631624912d",
        }
        mresponse = MagicMock()
        mresponse.status_code = requests.codes.created
        mresponse.json = Mock(return_value=resp_data)
        mpost.return_value = mresponse
        kid = skey.generate_rsa_key('test', 2048, 'description')
        mpost.assert_called_with(BASE_URL + 'crypto/v1/keys',
                                 headers=headers, data=json.dumps(req_data))
        self.assertEqual(kid, "fe0b726f-ae25-4939-a67b-382a4e7f35f7")

    @patch('aedkeyman.smartkey.requests.post')
    def test_21_gen_rsa_key_fail(self, mrequest):
        skey = aedkeyman.SmartKey()
        skey.token = BEARER_TOKEN
        with self.assertRaises(aedkeyman.SmartKeyException):
            skey.generate_rsa_key('test', 2048, 'test')

    @patch('aedkeyman.SmartKey.auth_app', new=Mock())
    @patch('aedkeyman.smartkey.requests.post')
    def test_22_export_rsa_success(self, mpost):
        skey = aedkeyman.SmartKey(apikey=API_KEY)
        skey.token = BEARER_TOKEN
        headers = {
            'Authorization': 'Bearer ' + BEARER_TOKEN,
        }
        req_data = {
            'kid': 'fe0b726f-ae25-4939-a67b-382a4e7f35f7',
        }
        resp_data = {
            'acct_id': 'bf6ea1a8-4e77-478f-a4e2-2524197614a8',
            'created_at': '20180809T152604Z',
            'creator': {'app': 'ff16d3e7-4811-493f-a501-9e1d1ec93b9c'},
            'description': 'test',
            'enabled': True,
            'group_id': '8820a695-2476-431a-8aea-8f631624912d',
            'key_ops': ['EXPORT'],
            'key_size': 2048,
            'kid': 'fe0b726f-ae25-4939-a67b-382a4e7f35f7',
            'lastused_at': '19700101T000000Z',
            'name': 'test',
            'never_exportable': False,
            'obj_type': 'RSA',
            'origin': 'FortanixHSM',
            'pub_key': test_rsa_pub,
            'public_only': False,
            'rsa': {
                'encryption_policy': [{'padding': {'OAEP': {'mgf': None}}}],
                'key_size': 2048,
                'signature_policy': [{'padding': None}],
            },
            'value': test_rsa_priv,
        }
        mresponse = MagicMock()
        mresponse.status_code = requests.codes.ok
        mresponse.json = Mock(return_value=resp_data)
        mpost.return_value = mresponse
        actual_rdata = skey.export_key('fe0b726f-ae25-4939-a67b-382a4e7f35f7')
        mpost.assert_called_with(BASE_URL + 'crypto/v1/keys/export',
                                 headers=headers, data=json.dumps(req_data))
        expected_rdata = resp_data
        self.assertEqual(actual_rdata, expected_rdata)

    @patch('aedkeyman.SmartKey.auth_app', new=Mock())
    @patch('aedkeyman.smartkey.requests.get')
    def test_30_list_keys_success(self, mget):
        skey = aedkeyman.SmartKey(apikey=API_KEY)
        skey.token = BEARER_TOKEN
        headers = {
            'Authorization': 'Bearer ' + BEARER_TOKEN,
        }
        resp_data = [list_ec1, list_rsa1, list_cert1]
        mresponse = MagicMock()
        mresponse.status_code = requests.codes.ok
        mresponse.json = Mock(return_value=resp_data)
        mget.return_value = mresponse
        actual_rdata = skey.list_keys()
        mget.assert_called_with(url=BASE_URL + 'crypto/v1/keys',
                                headers=headers, params=None)
        expected_rdata = resp_data
        self.assertEqual(actual_rdata, expected_rdata)

    @patch('aedkeyman.SmartKey.auth_app', new=Mock())
    @patch('aedkeyman.smartkey.requests.get')
    def test_31_list_keys_filter_name_success(self, mget):
        skey = aedkeyman.SmartKey(apikey=API_KEY)
        skey.token = BEARER_TOKEN
        headers = {
            'Authorization': 'Bearer ' + BEARER_TOKEN,
        }
        resp_data = [list_rsa1]
        mresponse = MagicMock()
        mresponse.status_code = requests.codes.ok
        mresponse.json = Mock(return_value=resp_data)
        mget.return_value = mresponse
        name = "example.com-key"
        actual_rdata = skey.list_keys(name=name)
        mget.assert_called_with(url=BASE_URL + 'crypto/v1/keys',
                                headers=headers, params={'name': name})
        expected_rdata = resp_data
        self.assertEqual(actual_rdata, expected_rdata)

    @patch('aedkeyman.SmartKey.auth_app', new=Mock())
    @patch('aedkeyman.smartkey.requests.get')
    def test_32_list_groups_success(self, mget):
        skey = aedkeyman.SmartKey(apikey=API_KEY)
        skey.token = BEARER_TOKEN
        headers = {
            'Authorization': 'Bearer ' + BEARER_TOKEN,
        }
        resp_data = [
            {
                "created_at": "20180814T170246Z",
                "creator": {"user": "fae8b863-c1f9-4b68-82bd-8e86c47c7a01"},
                "description": "",
                "group_id": "39381c80-c512-405a-abbe-2e5a07e5d440",
                "name": "second",
                "acct_id": "bf6ea1a8-4e77-478f-a4e2-2524197614a8",
            }, {
                "created_at": "20180523T175159Z",
                "creator": {"user": "fae8b863-c1f9-4b68-82bd-8e86c47c7a01"},
                "description": "",
                "group_id": "8820a695-2476-431a-8aea-8f631624912d",
                "name": "test",
                "acct_id": "bf6ea1a8-4e77-478f-a4e2-2524197614a8",
            },
        ]
        mresponse = MagicMock()
        mresponse.status_code = requests.codes.ok
        mresponse.json = Mock(return_value=resp_data)
        mget.return_value = mresponse
        actual_rdata = skey.list_groups()
        mget.assert_called_with(url=BASE_URL + 'sys/v1/groups',
                                headers=headers, params=None)
        expected_rdata = resp_data
        self.assertEqual(actual_rdata, expected_rdata)

    @patch('aedkeyman.SmartKey.auth_app', new=Mock())
    @patch('aedkeyman.smartkey.requests.delete')
    def test_40_delete_key_success(self, mdel):
        kid = '834c17f1-10ba-43f8-8687-5dd8c73344d8'
        skey = aedkeyman.SmartKey(apikey=API_KEY)
        skey.token = BEARER_TOKEN
        headers = {'Authorization': 'Bearer ' + BEARER_TOKEN}
        resp_data = None
        mresponse = MagicMock()
        mresponse.status_code = 204
        mresponse.json = Mock(return_value=resp_data)
        mdel.return_value = mresponse
        skey.delete_key(kid)
        mdel.assert_called_with(url=BASE_URL + 'crypto/v1/keys/' + kid,
                                headers=headers)

    @patch('aedkeyman.SmartKey.auth_app', new=Mock())
    @patch('aedkeyman.smartkey.requests.delete')
    def test_41_delete_key_fail(self, mdel):
        kid = '834c17f1-10ba-43f8-8687-5dd8c73344d8'
        skey = aedkeyman.SmartKey(apikey=API_KEY)
        skey.token = BEARER_TOKEN
        headers = {'Authorization': 'Bearer ' + BEARER_TOKEN}
        resp_data = 'Sobject does not exist'
        mresponse = MagicMock()
        mresponse.status_code = 404
        mresponse.json = Mock(return_value=resp_data)
        mdel.return_value = mresponse
        with self.assertRaises(aedkeyman.SmartKeyException):
            skey.delete_key(kid)
        mdel.assert_called_with(url=BASE_URL + 'crypto/v1/keys/' + kid,
                                headers=headers)


if __name__ == '__main__':
    unittest.main()
