# Copyright (c) 2019 NETSCOUT Systems, Inc.
"""Test aedkeyman proper."""

import sys
import unittest

from aedkeyman import command_line

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

BASE_URL = 'https://www.smartkey.io/'

BEARER_TOKEN = ("25mjpor8S9igwuXhFi8UuWqb-O54cO1cZVG5r_BRIryMF7JUu7oXdV5ImI"
                + "F88UyEkURTEKp7Xi-c9dO2gC7r4w")

API_KEY = ("ZmYxNmQzZTctNDgxMS00OTNmLWE1MDEtOWUxZDFlYzkzYjljOmVIamhBUU"
           + "1Xd3NzcFBDMTNDZ3hUVEdhQTNZeEhabzVvcFl2UVRkM1FjRFJHRzJEQXVO"
           + "YWlJSXFrU21yTTNuTjZaeU90UDlMQnc1aWs4NjhtdTRTcm5B")

rsa2048_pub_pkcs8 = ('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1xz7'
                     + 'YS11AbUqC8otGgQ11LUaMNlzl7ASttlM6925JzGm+/OtQXpM'
                     + '4oevMQxqlwiwGiXex3bRxp6eS1jWoZPApc2yJenNOmbi2Jfu'
                     + 'hrsuZpm+MGkhPu42++4qGRCrqJhmvEIuC9D8GrYRvd7kC0ch'
                     + 'MxdoUFLXT27Je7LRpDkz9jWpx5gllVTuzWVnmEhS+vjgLzU1'
                     + 'oSLQh+lTFmp5TG63G/7T3BT4poJNubpAUvF4LZd9UjDHWv/N'
                     + '1O5zIZvR6WxHuq0a21nUTi6Is0KWSF0lb6ofaYtjzJ/Oqjs8'
                     + '52T+0fch1UD07FnrlR1nbyXYukiYlwRtKNLy4Q6g3SUiKUue'
                     + '1QIDAQAB')

rsa2048_pub = ('MIIBCgKCAQEA1xz7YS11AbUqC8otGgQ11LUaMNlzl7AStt'
               + 'lM6925JzGm+/OtQXpM4oevMQxqlwiwGiXex3bRxp6eS1jW'
               + 'oZPApc2yJenNOmbi2JfuhrsuZpm+MGkhPu42++4qGRCrqJ'
               + 'hmvEIuC9D8GrYRvd7kC0chMxdoUFLXT27Je7LRpDkz9jWp'
               + 'x5gllVTuzWVnmEhS+vjgLzU1oSLQh+lTFmp5TG63G/7T3B'
               + 'T4poJNubpAUvF4LZd9UjDHWv/N1O5zIZvR6WxHuq0a21nU'
               + 'Ti6Is0KWSF0lb6ofaYtjzJ/Oqjs852T+0fch1UD07FnrlR'
               + '1nbyXYukiYlwRtKNLy4Q6g3SUiKUue1QIDAQAB')

rsa2048_priv = (
    'MIIEpAIBAAKCAQEA1xz7YS11AbUqC8otGgQ11LUaMNlzl7AS'
    + 'ttlM6925JzGm+/OtQXpM4oevMQxqlwiwGiXex3bRxp6eS1jW'
    + 'oZPApc2yJenNOmbi2JfuhrsuZpm+MGkhPu42++4qGRCrqJhm'
    + 'vEIuC9D8GrYRvd7kC0chMxdoUFLXT27Je7LRpDkz9jWpx5gl'
    + 'lVTuzWVnmEhS+vjgLzU1oSLQh+lTFmp5TG63G/7T3BT4poJN'
    + 'ubpAUvF4LZd9UjDHWv/N1O5zIZvR6WxHuq0a21nUTi6Is0KW'
    + 'SF0lb6ofaYtjzJ/Oqjs852T+0fch1UD07FnrlR1nbyXYukiY'
    + 'lwRtKNLy4Q6g3SUiKUue1QIDAQABAoIBAA2WGcVxPMzjD5kH'
    + 'h7I3NlwtJQ6VSWD5ALGWR261RhK05t5ObXCvhAghuD2xklDg'
    + 'Plkkb63q8gRos8g//+xcG+SM+ZW97tWjtmumKu1NCLj3uGSv'
    + '2ybxnjzqtbN4E1N2brSwvF5IMIgSXEwA9ifFMhJbRd4e4VT1'
    + 'wxmCOY31A/RmoR9dsUV8DGfptCzj8r+frnAinjHHNTXo1N3b'
    + 'mKFWryqz6tF2l3HxOnixuS3RT2Id1GHx+OxNr9fGGTyf2BPF'
    + 'nIe4UspaPGrUZqsh+hgF4hCDY/fSph71kdE1i387VUUUQcj3'
    + 'oWc4zbGIzAjUHOE6xVlrjCcklXsKQNpx+LW69jECgYEA8RJm'
    + 'PSgdJ013VfZF24byDgKDsXS1TPdPCSGSseCKqskBZjcQo9TG'
    + '/JMvjgR5N+zEHeJwCT3nft1W74f9qi2hU1P2fPhzkwlJxFZm'
    + 'w1BfOkvS8TSgfBTJnKVhJ/SsbhLg7hyYUCjAscQ9QYLoHsnf'
    + 'D26Z7emQ76Oh5iDyoyMx53ECgYEA5G8Sa1h+rZqMXFaQbX3N'
    + 'hBa0EAQUJVF8OsrOAgaFCRGY2TA5ep8BqGP1j3f8NFordVgi'
    + '5uJ5Azj3u1df7LlyR0VnAOxgN0baYHpR3EbVK+J8j3abd1nZ'
    + 'NXMeOXOe2jnd4iGeRtvMgJA7Cx6vBF2/k1HkCYpjI7emmAbX'
    + 'hnLNI6UCgYEAvOaoCqAWSCfhrRBvqRfTMLszqqhDMO5Rllwi'
    + 'cRP8VNtxJ0Fa3qXqzxwelXBX9ESpYKmBFRzW+4hBiSzMzr82'
    + 'vO78JO0i00Lh9OGnYMDn/exQfQW6A8DeQsssmHyXaSGN88eg'
    + 'ap+kbyfQwDbt4MJa8eK+57iwA7f7MzL6Lm9zuWECgYEA0q6O'
    + 'cmrgCwVrRw6fjhxlG9pEoDDi07hft2msrrmMoVyVeFq96JYW'
    + 'VVQ7+uJSvYYcZtGu/vsJWSuFcEeZtR8kgw9DfNqFsvWqGyk1'
    + 'rs+1dBAjib1+jYlUh7NwwNQeQm70ccdHz1qRNlHP4uWdzY0Z'
    + 'T6pLg3EbFqofAD/vL5VaFfECgYAqLllH8/qRK1dpaMXqfuQc'
    + '5UNBCcELEh8u0x18dbvf/ODJka8Ny+ZFrDxv7vffzD1XaVV6'
    + 'Bqrr9LNAig+W++eVVSjQo4NQOLIK/kxtUihW02fz7fm6QWbZ'
    + 'i7g0cQcu5hjoCSemIbfYQRAOCXUe/S8i90mjRfBEvtW1PLzr'
    + 'viF2/g=='
)

# nist256_pub_pkcs8 = ('QgAE0tN9OH6PZvKPI59DNKe1LX+MeNpPY8Jfv88PefDi' +
#                     'xh02YNvcp8hHE7HhOZxiT7pRsTmrbp8PUbe0bO+ZsKyN' +
#                      'SQ==')

nist256_pub_pkcs8 = ('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0tN9OH6PZ'
                     + 'vKPI59DNKe1LX+MeNpPY8Jfv88PefDixh02YNvcp8hHE7'
                     + 'HhOZxiT7pRsTmrbp8PUbe0bO+ZsKyNSQ==')

nist256_pub = ('BNLTfTh+j2byjyOfQzSntS1/jHjaT2PCX7/PD3nw4sYdNmDb3K'
               + 'fIRxOx4TmcYk+6UbE5q26fD1G3tGzvmbCsjUk=')

nist256_priv = ('MHcCAQEEIB4NWQ42ppxbEfSo1GtuLPxJVLDOpQ2lLAzxjlvG'
                + 'dZ/KoAoGCCqGSM49AwEHoUQDQgAE0tN9OH6PZvKPI59DNKe1'
                + 'LX+MeNpPY8Jfv88PefDixh02YNvcp8hHE7HhOZxiT7pRsTmr'
                + 'bp8PUbe0bO+ZsKyNSQ==')


class KeyManTestCase(unittest.TestCase):
    def test_00_util(self):
        self.assertEqual(rsa2048_pub,
                         command_line.pkcs8_to_pub(rsa2048_pub_pkcs8))
        self.assertEqual(nist256_pub,
                         command_line.pkcs8_to_pub(nist256_pub_pkcs8))

    @patch('aedkeyman.SmartKey.export_key')
    @patch('aedkeyman.SmartKey.list_keys')
    @patch('aedkeyman.SmartKey._fetch_token')
    @patch('aedkeyman.ArborEdgeDefense.import_key')
    @patch('aedkeyman.ArborEdgeDefense.list_keys')
    @patch('os.getenv')
    def test_05_sync_no_keys(self, getenv, aed_list_keys, aed_import_key,
                             ska_fetch_token, ska_list_keys,
                             ska_export_key):
        """Do nothing when there are no keys."""
        args = object()
        getenv.return_value = ""
        ska_list_keys.return_value = {}
        aed_list_keys.return_value = {}
        command_line.cmd_skey_sync_keys(args)
        ska_export_key.assert_not_called()
        aed_import_key.assert_not_called()

    @patch('aedkeyman.smartkey.SmartKey.export_key')
    @patch('aedkeyman.smartkey.SmartKey.list_keys')
    @patch('aedkeyman.smartkey.SmartKey._fetch_token')
    @patch('aedkeyman.aed.ArborEdgeDefense.import_key')
    @patch('aedkeyman.aed.ArborEdgeDefense.list_keys')
    @patch('os.getenv')
    def test_05_sync(self, getenv, aed_list_keys, aed_import_key,
                     ska_fetch_token, ska_list_keys, ska_export_key):
        """
        Test 2 keys in SmartKey and zero on APS.

        Assert that we push both.
        """
        args = object()
        getenv.return_value = ""

        # None returned by AED
        aed_list_keys.return_value = []

        # Two returned by SmartKey
        ska_list_keys.return_value = [{
            'acct_id': '79f56d41-d52c-4747-a32b-06670967f02e',
            'activation_date': '20190514T144829Z',
            'created_at': '20190514T144829Z',
            'creator': {'user': 'a7fa826c-b553-4d63-93e7-9f5af2a44f63'},
            'description': '',
            'enabled': True,
            'group_id': '4dbe167a-8e58-43b9-922a-4ac6f94c052a',
            'key_ops': ['SIGN', 'VERIFY', 'ENCRYPT', 'DECRYPT',
                        'WRAPKEY', 'UNWRAPKEY', 'EXPORT',
                        'APPMANAGEABLE'],
            'key_size': 2048,
            'kid': '0b8358fc-1864-4096-9ab9-26fb59e86abe',
            'lastused_at': '19700101T000000Z',
            'name': 'testkey2048',
            'never_exportable': False,
            'obj_type': 'RSA',
            'origin': 'FortanixHSM',
            'pub_key': rsa2048_pub_pkcs8,
            'public_only': False,
            'rsa': {
                'encryption_policy': [{
                    'padding': {'OAEP':
                                {'mgf': None}}}],
                'key_size': 2048,
                'signature_policy': [{'padding': None}],
            },
            'state': 'Active',
        }, {
            'acct_id': '79f56d41-d52c-4747-a32b-06670967f02e',
            'activation_date': '20190514T195343Z',
            'created_at': '20190514T195343Z',
            'creator': {'user': 'a7fa826c-b553-4d63-93e7-9f5af2a44f63'},
            'description': '',
            'elliptic_curve': 'NistP256',
            'enabled': True,
            'group_id': '4dbe167a-8e58-43b9-922a-4ac6f94c052a',
            'key_ops': ['SIGN', 'VERIFY', 'EXPORT', 'APPMANAGEABLE',
                        'AGREEKEY'],
            'kid': '6e7b1ebb-7f66-423e-8a57-1074f407341d',
            'lastused_at': '19700101T000000Z',
            'name': 'nist256',
            'never_exportable': False,
            'obj_type': 'EC',
            'origin': 'FortanixHSM',
            'pub_key': nist256_pub_pkcs8,
            'public_only': False,
            'state': 'Active',
        }]

        # Export is called twice
        ska_export_key.side_effect = [
            {'acct_id': '79f56d41-d52c-4747-a32b-06670967f02e',
             'activation_date': '20190514T144829Z',
             'created_at': '20190514T144829Z',
             'creator': {'user': 'a7fa826c-b553-4d63-93e7-9f5af2a44f63'},
             'description': '',
             'enabled': True,
             'group_id': '4dbe167a-8e58-43b9-922a-4ac6f94c052a',
             'key_ops': ['SIGN',
                         'VERIFY',
                         'ENCRYPT',
                         'DECRYPT',
                         'WRAPKEY',
                         'UNWRAPKEY',
                         'EXPORT',
                         'APPMANAGEABLE'],
             'key_size': 2048,
             'kid': '0b8358fc-1864-4096-9ab9-26fb59e86abe',
             'lastused_at': '19700101T000000Z',
             'name': 'testkey2048',
             'never_exportable': False,
             'obj_type': 'RSA',
             'origin': 'FortanixHSM',
             'pub_key': rsa2048_pub_pkcs8,
             'public_only': False,
             'rsa': {
                 'encryption_policy': [{'padding': {'OAEP': {'mgf': None}}}],
                 'key_size': 2048,
                 'signature_policy': [{'padding': None}]},
             'state': 'Active',
             'value': rsa2048_priv,
             },  # Second key
            {'acct_id': '79f56d41-d52c-4747-a32b-06670967f02e',
             'activation_date': '20190514T195343Z',
             'created_at': '20190514T195343Z',
             'creator': {'user': 'a7fa826c-b553-4d63-93e7-9f5af2a44f63'},
             'description': '',
             'elliptic_curve': 'NistP256',
             'enabled': True,
             'group_id': '4dbe167a-8e58-43b9-922a-4ac6f94c052a',
             'key_ops': ['SIGN', 'VERIFY', 'EXPORT', 'APPMANAGEABLE',
                         'AGREEKEY'],
             'kid': '6e7b1ebb-7f66-423e-8a57-1074f407341d',
             'lastused_at': '19700101T000000Z',
             'name': 'nist256',
             'never_exportable': False,
             'obj_type': 'EC',
             'origin': 'FortanixHSM',
             'pub_key': nist256_pub_pkcs8,
             'public_only': False,
             'state': 'Active',
             'value': nist256_priv,
             },
        ]

        aed_import_key.side_effect = [
            {"label": "testkey2048", "type": "RSA"},
            {"label": "nist256", "type": "EC"},
        ]
        command_line.cmd_skey_sync_keys(args)

        # Make sure export was called twice with the correct kid
        self.assertEqual(ska_export_key.call_count, 2)
        ska_export_key.assert_any_call(
            '0b8358fc-1864-4096-9ab9-26fb59e86abe')
        ska_export_key.assert_any_call(
            '6e7b1ebb-7f66-423e-8a57-1074f407341d')

        # Make sure import was called twice with the correct data
        self.assertEqual(aed_import_key.call_count, 2)
        aed_import_key.assert_any_call('testkey2048',
                                       ("-----BEGIN RSA PRIVATE KEY-----\n"
                                        + "%s\n-----END RSA PRIVATE KEY-----\n")
                                       % rsa2048_priv)

        aed_import_key.assert_any_call('nist256',
                                       ("-----BEGIN EC PARAMETERS-----\n"
                                        + "BggqhkjOPQMBBw==\n"
                                        + "-----END EC PARAMETERS-----\n-----"
                                        + "BEGIN EC PRIVATE KEY-----\n%s\n---"
                                        + "--END EC PRIVATE KEY-----\n") %
                                       nist256_priv)

    @patch('aedkeyman.smartkey.SmartKey.export_key')
    @patch('aedkeyman.smartkey.SmartKey.list_keys')
    @patch('aedkeyman.smartkey.SmartKey._fetch_token')
    @patch('aedkeyman.aed.ArborEdgeDefense.import_key')
    @patch('aedkeyman.aed.ArborEdgeDefense.list_keys')
    @patch('os.getenv')
    def test_10_sync_noop(self, getenv, aed_list_keys,
                          aed_import_key, ska_fetch_token,
                          ska_list_keys, ska_export_key):
        """Test 2 keys in SmartKey with the same two on APS.

        Assertno action.
        """
        args = object()
        getenv.return_value = ""

        # Two returned by AED
        aed_list_keys.return_value = [
            {
                "label": "testkey2048",
                "public": rsa2048_pub,
                "type": "RSA",
            },
            {
                "label": "nist256",
                "public": nist256_pub,
                "type": "EC",
            },
        ]

        # Two returned by SmartKey
        ska_list_keys.return_value = [{
            'acct_id': '79f56d41-d52c-4747-a32b-06670967f02e',
            'activation_date': '20190514T144829Z',
            'created_at': '20190514T144829Z',
            'creator': {'user': 'a7fa826c-b553-4d63-93e7-9f5af2a44f63'},
            'description': '',
            'enabled': True,
            'group_id': '4dbe167a-8e58-43b9-922a-4ac6f94c052a',
            'key_ops': ['SIGN', 'VERIFY', 'ENCRYPT', 'DECRYPT',
                        'WRAPKEY', 'UNWRAPKEY', 'EXPORT',
                        'APPMANAGEABLE'],
            'key_size': 2048,
            'kid': '0b8358fc-1864-4096-9ab9-26fb59e86abe',
            'lastused_at': '19700101T000000Z',
            'name': 'testkey2048',
            'never_exportable': False,
            'obj_type': 'RSA',
            'origin': 'FortanixHSM',
            'pub_key': rsa2048_pub_pkcs8,
            'public_only': False,
            'rsa': {
                'encryption_policy': [{
                    'padding': {'OAEP':
                                {'mgf': None}}}],
                'key_size': 2048,
                'signature_policy': [{'padding': None}],
            },
            'state': 'Active',
        }, {
            'acct_id': '79f56d41-d52c-4747-a32b-06670967f02e',
            'activation_date': '20190514T195343Z',
            'created_at': '20190514T195343Z',
            'creator': {'user': 'a7fa826c-b553-4d63-93e7-9f5af2a44f63'},
            'description': '',
            'elliptic_curve': 'NistP256',
            'enabled': True,
            'group_id': '4dbe167a-8e58-43b9-922a-4ac6f94c052a',
            'key_ops': ['SIGN', 'VERIFY', 'EXPORT', 'APPMANAGEABLE',
                        'AGREEKEY'],
            'kid': '6e7b1ebb-7f66-423e-8a57-1074f407341d',
            'lastused_at': '19700101T000000Z',
            'name': 'nist256',
            'never_exportable': False,
            'obj_type': 'EC',
            'origin': 'FortanixHSM',
            'pub_key': nist256_pub_pkcs8,
            'public_only': False,
            'state': 'Active',
        }]

        # Export is called twice
        command_line.cmd_skey_sync_keys(args)

        # Make sure no action was taken
        ska_export_key.assert_not_called()
        aed_import_key.assert_not_called()

    @patch('aedkeyman.smartkey.SmartKey.export_key')
    @patch('aedkeyman.smartkey.SmartKey.list_keys')
    @patch('aedkeyman.smartkey.SmartKey._fetch_token')
    @patch('aedkeyman.aed.ArborEdgeDefense.import_key')
    @patch('aedkeyman.aed.ArborEdgeDefense.list_keys')
    @patch('os.getenv')
    def test_15_sync_one_out_of_two(self, getenv, aed_list_keys,
                                    aed_import_key, ska_fetch_token,
                                    ska_list_keys, ska_export_key):
        """
        Test 2 keys in SmartKey with one missing on APS.

        Assert one action.
        """
        args = object()
        getenv.return_value = ""

        # One returned by AED
        aed_list_keys.return_value = [
            {
                "label": "testkey2048",
                "public": rsa2048_pub,
                "type": "RSA",
            },
        ]

        # Two returned by SmartKey
        ska_list_keys.return_value = [{
            'acct_id': '79f56d41-d52c-4747-a32b-06670967f02e',
            'activation_date': '20190514T144829Z',
            'created_at': '20190514T144829Z',
            'creator': {'user': 'a7fa826c-b553-4d63-93e7-9f5af2a44f63'},
            'description': '',
            'enabled': True,
            'group_id': '4dbe167a-8e58-43b9-922a-4ac6f94c052a',
            'key_ops': ['SIGN', 'VERIFY', 'ENCRYPT', 'DECRYPT',
                        'WRAPKEY', 'UNWRAPKEY', 'EXPORT',
                        'APPMANAGEABLE'],
            'key_size': 2048,
            'kid': '0b8358fc-1864-4096-9ab9-26fb59e86abe',
            'lastused_at': '19700101T000000Z',
            'name': 'testkey2048',
            'never_exportable': False,
            'obj_type': 'RSA',
            'origin': 'FortanixHSM',
            'pub_key': rsa2048_pub_pkcs8,
            'public_only': False,
            'rsa': {
                'encryption_policy': [{
                    'padding': {'OAEP':
                                {'mgf': None}}}],
                'key_size': 2048,
                'signature_policy': [{'padding': None}],
            },
            'state': 'Active',
        }, {
            'acct_id': '79f56d41-d52c-4747-a32b-06670967f02e',
            'activation_date': '20190514T195343Z',
            'created_at': '20190514T195343Z',
            'creator': {'user': 'a7fa826c-b553-4d63-93e7-9f5af2a44f63'},
            'description': '',
            'elliptic_curve': 'NistP256',
            'enabled': True,
            'group_id': '4dbe167a-8e58-43b9-922a-4ac6f94c052a',
            'key_ops': ['SIGN', 'VERIFY', 'EXPORT', 'APPMANAGEABLE',
                        'AGREEKEY'],
            'kid': '6e7b1ebb-7f66-423e-8a57-1074f407341d',
            'lastused_at': '19700101T000000Z',
            'name': 'nist256',
            'never_exportable': False,
            'obj_type': 'EC',
            'origin': 'FortanixHSM',
            'pub_key': nist256_pub_pkcs8,
            'public_only': False,
            'state': 'Active',
        }]

        # Export is called once
        ska_export_key.side_effect = [
            {'acct_id': '79f56d41-d52c-4747-a32b-06670967f02e',
             'activation_date': '20190514T195343Z',
             'created_at': '20190514T195343Z',
             'creator': {'user': 'a7fa826c-b553-4d63-93e7-9f5af2a44f63'},
             'description': '',
             'elliptic_curve': 'NistP256',
             'enabled': True,
             'group_id': '4dbe167a-8e58-43b9-922a-4ac6f94c052a',
             'key_ops': ['SIGN', 'VERIFY', 'EXPORT', 'APPMANAGEABLE',
                         'AGREEKEY'],
             'kid': '6e7b1ebb-7f66-423e-8a57-1074f407341d',
             'lastused_at': '19700101T000000Z',
             'name': 'nist256',
             'never_exportable': False,
             'obj_type': 'EC',
             'origin': 'FortanixHSM',
             'pub_key': nist256_pub_pkcs8,
             'public_only': False,
             'state': 'Active',
             'value': nist256_priv,
             },
        ]

        aed_import_key.side_effect = [
            {"label": "nist256", "type": "EC"},
        ]
        command_line.cmd_skey_sync_keys(args)

        # Make sure export was called twice with the correct kid
        self.assertEqual(ska_export_key.call_count, 1)
        ska_export_key.assert_called_with(
            '6e7b1ebb-7f66-423e-8a57-1074f407341d')

        # Make sure import was called once with the correct data
        self.assertEqual(aed_import_key.call_count, 1)
        aed_import_key.assert_called_with(
            'nist256', (
                ("-----BEGIN EC PARAMETERS-----\n"
                 + "BggqhkjOPQMBBw==\n"
                 + "-----END EC PARAMETERS-----\n-----"
                 + "BEGIN EC PRIVATE KEY-----\n%s\n---"
                 + "--END EC PRIVATE KEY-----\n") %
                nist256_priv))


if __name__ == '__main__':
    unittest.main()
