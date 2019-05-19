# Copyright (c) 2019 NETSCOUT Systems, Inc.

"""Test AED connection management and interface."""

import sys
import unittest

import aedkeyman

import requests


try:
    from unittest.mock import patch, Mock, MagicMock
except ImportError:
    from mock import patch, Mock, MagicMock


AED_HOST = 'nicotine.tb.arbor.net'
AED_TOKEN = 'cOiEeOPFkKtLgPRagMbHd36ciDu7P2tWM_NqID6v'
AED_USER = 'arbor_cu'
AED_PASS = 'password'

BASE_URL = 'https://%s/api/aps/' % (AED_HOST,)

HEADERS = {
    'X-Arbux-APIToken': AED_TOKEN,
    'X-Arbux-HSMUsername': AED_USER,
    'X-Arbux-HSMPassword': AED_PASS,
}


class ArborEdgeDefenseTestCase(unittest.TestCase):
    @patch('aedkeyman.aed.requests.post')
    def test_00_import_rsa_key_success(self, mpost):
        aed = aedkeyman.ArborEdgeDefense(AED_HOST, AED_TOKEN,
                                         AED_USER, AED_PASS)
        expected_rdata = {
            "label": "newrsa",
            "type": "RSA",
        }
        mresp = MagicMock()
        mresp.status_code = 201
        mresp.json = Mock(return_value=expected_rdata)
        mpost.return_value = mresp
        priv = ('-----BEGIN RSA PRIVATE KEY-----\n'
                + 'nMIIJJwIBAAKCAgEAj0dAiv5ZtkHLpQu'
                + 'cO7mL3JCqa56sJPgOpNrMPN2skjr5Zfr'
                + 'puY3xHR/K/YKMUwx7YYIyL8K1Z8FFm6j'
                + 'aebCKhsEy86qVJt2IkisXHKH3tUYd/K9'
                + '4hbIE2hUy6H00vqSOIMBlrUnabPDZik3'
                + 'rbpeNVEyrs4Le0/XceOoNzbBmKQvWf3s'
                + '6VCq4C6JQbrLSWcy+kg4V5ITgM6YjMgA'
                + 'MBpirGDqWdHdphJ1LWmj4mcorVsLWtCT'
                + 'E83d43j7tEX1elH5YVUT5EoQGqWRRnL7'
                + 'S97RtPi/wbhN/SXpF4F4nT02NJkyKQKl'
                + 'V87tqagTAio5xfaf5WPS9vuABm9Ntf7R'
                + 'UG8jn8HZen526M8TJmQoTikSUBUEkMDN'
                + 'CXhdRRzsSMZJTfM3mDDjepfjJzq0oUs+'
                + 'BBmVKA/JadIXc+7XqH1V15UIl1Whf7nl'
                + 'vlcWhLKhfx6O9drBHpsAUOlo4D/Bnk0E'
                + 'v/EF0cIUld3W9aiPNc3PBbtADi1IfevB'
                + 'hDg9qJ6jCz5IzUibdMHQ6H2fdKRgCBMz'
                + 'rIPsZd+20Lvv9/BrbecI924HN1tzNQ4a'
                + 'MDRq4Oe6LHqZyutz6OJh3zLo+Bza3HG4'
                + 'O0WZCp6Fat5kTnq2ier9AX3F0TF4qfoY'
                + 'fygjZajYqUBdtkgjALFTX+pRnLZBnT+9'
                + '4EWv6cFZ9PwY418bIaa5OoktF0XkCAwE'
                + 'AAQKCAgAGQbZo8207uyEPVKPWjFZWFAe'
                + 'rIi9SgHYUPx082bHJ43MlX8kB0jfZnZw'
                + 'tyJwD2udO5WJ3aTVmgd8+KkgbGQldk9V'
                + '7pEL14uXuOx074ftJElYoJQn6baEOXG9'
                + 'gDWqmmhU+SySNhgx4piZbxqYNqubQK/Z'
                + 'yBPih0SpW6eKfLTEy4OpVoA4Wo5RspqK'
                + 'ESQEMTJd0VZLhayeGvd4q1mtwBM3w5Ys'
                + 'RLC9CjCNgn/WeMqDEncbGMFZc6uZPbzh'
                + 'HQ54kFiXZmGTXiQYo8sFpGsCn8jw0g1+'
                + 'okOelr+YaA4aMLR7pMZ22b+aZ2YDuvwU'
                + 'g79I3KmUGPE7GZW4QjdGp6lgja/kr22K'
                + 'DQ8UikG6LHESD9zMT7eGRo9nbuos3dbI'
                + 'wm0mQgPNQYTXKaIaIRtAPjAuraJmkhRL'
                + 'wusKOcv5K58Gv8QbmMyHqSNVmxSl/e1b'
                + 'qnt03F1mtUXOUpy+Kr6Vx2Nzoii9mxmu'
                + 'Z1LFAet4ssAGccTibNJbd+YfCBXAcVAR'
                + 'KpztbBmkYqkeVcfmQ6dO0Xi+gBgx1P8y'
                + 'te8rc6qdYFloCj39+81o8WQJRRlRTZlK'
                + 'ScQmKvS2GBU6M/vKbAiiLM+wlOD+yrVp'
                + 'Cj8h4bT4LCthsFGMxMPIFI09okbVhdz4'
                + 'C6LoRafqji2ZQYUDAOSsG8H9p8YOPV61'
                + 'fpenRXpIXA8iTu4SGQQKCAQEAyN5gbWQ'
                + 'Fy88sX49z+mXIlIb3vnlzW0+6xhFCuXf'
                + 'MlNnLGWqoCEheMDiZIff83l/pyGA6EcF'
                + '/A4x0Ad44xWX+sI2pzt+fF+OndXaLi8j'
                + 'xvPGmZ7gkbKPtc7WaOVJ0rWPfrwGR3LI'
                + '/s8Z1JqiyjMJe9TQOWjjTowyi9kXf9LH'
                + 'fg7r+4B9Ckla54M/vjgTYK1XcdL3XxX1'
                + 'Uz4BsS//eX3piG3+yOirnwTuvb7xGJJH'
                + 'A5ki2OQa1MndYmhweIwNnlr+Bq2UKMlM'
                + 'WIl3NDcdAc30aPT6NGUX8tijbzHkuv1k'
                + 'RkWQJVcwjK3t8OAx8N/vtVH1/GysNE5h'
                + 'nzR5H5FL3hLJcQQKCAQEAtppox+7VMmK'
                + 'wITI04qt1RHV1ESWU+FLnoKGvNyAGoco'
                + '4d1ubESCXiVQxOINOIoLopOkD506UNPo'
                + '9zK38SBOUNTBj4pN81u5nb+dqbUjXxu7'
                + 'CQ+gaG8NauWvas452fvK51/8K6BP+sjU'
                + '2cDl327Ww3k4jxU+dr6ejka6ZoKh1mVE'
                + 'JjHqwrzGqnCo/7IxvA6uQFs58prM4RZ5'
                + 'dq+eQVmpcP2b58kDOWDEOg1PtLA/7I/G'
                + 'YTb8LYy5k7K662Xcq73cUMzeqvH//Wb+'
                + 'JmSU40OFDC4jyKswxnESvJCgFRLc/Mhu'
                + '31FtZreYSEntPj4NY3RY9+KvaSBnaqvB'
                + '9SYWiSqmHOQKCAQAnyUxGPpqbTPTYFLz'
                + '/Kuv452bo9ntv6bHwC3kw7Va7YQxGg4a'
                + '25UaqvHswbENM9KiExPKbk70Jwec0e4S'
                + '5LMOuytCIpmiHvdLshEeNr4aaSy8Pujy'
                + 'UvD+LPLxIgFmWAoNK0b/HfBL8E+Iefym'
                + 'mkdVnMiFpo3ngAN/CcgKzIAxKtl5HnEl'
                + '+XOlCa01izvjWVJJvGS9E8dc7po9M2mh'
                + '8duw50ChINzliX+UW967ZDXms41gcoYS'
                + 'Ac308QTeC7ei1xkbz4PaNE0H+GqBEC2R'
                + 'ru6rX2KzwBZnRpvQqYxJsWkMNjkf/E4k'
                + 'f0ry/CVINcLwIkTb89aEIcZaV3VqWEgz'
                + 'u3rlBAoIBACEue93g64LlZgYSPoP2DjA'
                + 're+NqxeA+CHMrDlDhE/NwcMRXtBzvpDn'
                + 'DP9J6IceprCbTZO8yW0IpOvOnphFe5W6'
                + 'o5W21yVixJ8Cw96j2NKekmU6Hrb7fx+u'
                + 'ryqkYOTYmW1kBsnSrtXuiqcrI1pvpL0O'
                + 'mRV/EcO4Lc3C0npwQIJaEoEyTuumLB+q'
                + 'qzsToW//5vAw453PPW2ljNrhXMuZRG4Q'
                + '17TN1TUm/WFjK9m0sVkGY1ElEbwhN1O8'
                + 'hbTi5K+cp51TLR85LIBap9JIMrn9ef7V'
                + 'n5EGcq2MvI/hZAWQUPHqZiNUg6HHuPdh'
                + '36eQ1RP+f3BEFAXxanl6zpsCmdPBGUBk'
                + 'CggEAEkOgRc5Qh9X3OcLPw3VgmN9Nfut'
                + 'eHIseNGzLj3vEiaAvCKv59ldYXFKjTBn'
                + 'tHdUgXMFp7HhKph/XTcAabQGhrEiGJrC'
                + 'M1Jr8j3eHaEBEsSHq6mFIGygUev4qE0k'
                + 'fzFsZXNuCtNi71x82eiVJa+Y3H2nOeQu'
                + 'd76SVvqC4Gtu6+iQCsFH11EISWvQB5gZ'
                + 'nKjbpHUTJvQ9ArEBnPp+dax7Px3l8oa1'
                + 'N3+grOn0/4LTl3IQ8k8fjcWlSPkbRu8b'
                + 'X8xwm4aHk51WHTe+GRj7RDiClWGt0UTy'
                + 'Gpb4aN9G0z8AilKi02dx8IicEuxyVFPT'
                + 'tXz8Z9KQQbkuejlUUv6GOWHv/+Q==\n-'
                + '----END RSA PRIVATE KEY-----')

        aed.import_key('newrsa', priv)

        body = {'privateKey': priv, 'certificate': None, 'label': 'newrsa'}

        mpost.assert_called_with(url=BASE_URL + 'v2/hsm/certificates/',
                                 headers=HEADERS, json=body,
                                 verify=True)

    @patch('aedkeyman.aed.requests.post')
    def test_import_rsa_key_fail(self, mpost):
        """Test that import raises when a public key is given as private."""
        aed = aedkeyman.ArborEdgeDefense(AED_HOST, AED_TOKEN,
                                         AED_USER, AED_PASS)
        expected_rdata = {
            "errors": [
                {
                    "code": "hsmError",
                    "message": "Certificate parse error",
                },
            ],
            "message": "HSM Error",
        }
        mresp = MagicMock()
        mresp.status_code = 422
        mresp.json = Mock(return_value=expected_rdata)
        mpost.return_value = mresp
        priv = ('-----BEGIN RSA PUBLIC KEY-----\n'
                + 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A'
                + 'MIICCgKCAgEAj0dAiv5ZtkHLpQucO7mL'
                + '3JCqa56sJPgOpNrMPN2skjr5ZfrpuY3x'
                + 'HR/K/YKMUwx7YYIyL8K1Z8FFm6jaebCK'
                + 'hsEy86qVJt2IkisXHKH3tUYd/K94hbIE'
                + '2hUy6H00vqSOIMBlrUnabPDZik3rbpeN'
                + 'VEyrs4Le0/XceOoNzbBmKQvWf3s6VCq4'
                + 'C6JQbrLSWcy+kg4V5ITgM6YjMgAMBpir'
                + 'GDqWdHdphJ1LWmj4mcorVsLWtCTE83d4'
                + '3j7tEX1elH5YVUT5EoQGqWRRnL7S97Rt'
                + 'Pi/wbhN/SXpF4F4nT02NJkyKQKlV87tq'
                + 'agTAio5xfaf5WPS9vuABm9Ntf7RUG8jn'
                + '8HZen526M8TJmQoTikSUBUEkMDNCXhdR'
                + 'RzsSMZJTfM3mDDjepfjJzq0oUs+BBmVK'
                + 'A/JadIXc+7XqH1V15UIl1Whf7nlvlcWh'
                + 'LKhfx6O9drBHpsAUOlo4D/Bnk0Ev/EF0'
                + 'cIUld3W9aiPNc3PBbtADi1IfevBhDg9q'
                + 'J6jCz5IzUibdMHQ6H2fdKRgCBMzrIPsZ'
                + 'd+20Lvv9/BrbecI924HN1tzNQ4aMDRq4'
                + 'Oe6LHqZyutz6OJh3zLo+Bza3HG4O0WZC'
                + 'p6Fat5kTnq2ier9AX3F0TF4qfoYfygjZ'
                + 'ajYqUBdtkgjALFTX+pRnLZBnT+94EWv6'
                + 'cFZ9PwY418bIaa5OoktF0XkCAwEAAQ=='
                + '\n-----END RSA PUBLIC KEY-----')

        with self.assertRaises(aedkeyman.ArborEdgeDefenseException):
            aed.import_key('newrsa', priv)

        body = {'privateKey': priv, 'certificate': None, 'label': 'newrsa'}

        mpost.assert_called_with(url=BASE_URL + 'v2/hsm/certificates/',
                                 headers=HEADERS, json=body,
                                 verify=True)

    @patch('aedkeyman.aed.requests.get')
    def test_list_keys_success(self, mget):
        aed = aedkeyman.ArborEdgeDefense(AED_HOST, AED_TOKEN,
                                         AED_USER, AED_PASS)
        req_data = {
            'details': 1,
        }
        server_resp_data = [
            {
                "label": "firstec",
                "public": ("BF7PXST4hfxGVy9z9Pvro/HibHa72hbqrbvovk/ht4DTX7"
                           + "m3AuHFMjt9PX2+LMs4ivLbneJZLbTbmsS+0eO9Yb48r6L6"
                           + "98QE2u7+7wsUZPVToeFGqRGzh6xMB4AeaqP4Ow=="),
                "type": "EC",
            },
            {
                "label": "ecdirect",
                "public": ("BGcIUz8K9MyRDkfV73aS0D0xRuiOxrqtUk2NREQeT+KgMU/"
                           + "sYjuFWebLkt8Juy5GRBKra819IDnLUS375w1Rm7o="),
                "type": "EC",
            },
            {
                "label": "finaldirecttest",
                "public": ("MIIBCgKCAQEAs/X8vDUD2xBI0PkksK48GsOTmApV9fJ7h8"
                           + "KBTaDC4ji98ywaIiWA4I3uksXZznIBgC+qHC5YwCClxK3o"
                           + "6Gws9GYh9hav+ezox9Gza2n/UHClZdymITKrszt0QdmYfu"
                           + "UTqROfu+3Ib0BKZr//2NmbWjvoJC2AFBtQXALmtv7bxxh3"
                           + "idE3n8fDU3APOce7DrUFXd1mwbzsxwTmhFBCVgghLulFIp"
                           + "ycdyyW8KIYUnRCxxrzUd7Fg/TAaDh1m6A3dxQmj7PQs647"
                           + "bzSyMF/AcSNfTDJS+jHHB81U0M4S5T8Mgufhe0uIOCFNv6"
                           + "LThkxRktcYEaBrE55G/Uv3FDMmprN+XQIDAQAB"),
                "type": "RSA",
            },
        ]
        mresp = MagicMock()
        mresp.status_code = requests.codes.ok
        mresp.json = Mock(return_value=server_resp_data)
        mget.return_value = mresp
        actual_rdata = aed.list_keys()
        mget.assert_called_with(url=BASE_URL + 'v2/hsm/certificates/',
                                headers=HEADERS, params=req_data,
                                verify=True)
        expected_rdata = [
            {
                "name": "firstec",
                "public": ("BF7PXST4hfxGVy9z9Pvro/HibHa72hbqrbvovk/ht4DTX7"
                           + "m3AuHFMjt9PX2+LMs4ivLbneJZLbTbmsS+0eO9Yb48r6L6"
                           + "98QE2u7+7wsUZPVToeFGqRGzh6xMB4AeaqP4Ow=="),
                "type": "EC",
            },
            {
                "name": "ecdirect",
                "public": ("BGcIUz8K9MyRDkfV73aS0D0xRuiOxrqtUk2NREQeT+KgMU/"
                           + "sYjuFWebLkt8Juy5GRBKra819IDnLUS375w1Rm7o="),
                "type": "EC",
            },
            {
                "name": "finaldirecttest",
                "public": ("MIIBCgKCAQEAs/X8vDUD2xBI0PkksK48GsOTmApV9fJ7h8"
                           + "KBTaDC4ji98ywaIiWA4I3uksXZznIBgC+qHC5YwCClxK3o"
                           + "6Gws9GYh9hav+ezox9Gza2n/UHClZdymITKrszt0QdmYfu"
                           + "UTqROfu+3Ib0BKZr//2NmbWjvoJC2AFBtQXALmtv7bxxh3"
                           + "idE3n8fDU3APOce7DrUFXd1mwbzsxwTmhFBCVgghLulFIp"
                           + "ycdyyW8KIYUnRCxxrzUd7Fg/TAaDh1m6A3dxQmj7PQs647"
                           + "bzSyMF/AcSNfTDJS+jHHB81U0M4S5T8Mgufhe0uIOCFNv6"
                           + "LThkxRktcYEaBrE55G/Uv3FDMmprN+XQIDAQAB"),
                "type": "RSA",
            },
        ]
        self.assertEqual(actual_rdata, expected_rdata)

    @patch('aedkeyman.aed.requests.get')
    def test_list_keys_hsm_auth_error(self, mget):
        aed = aedkeyman.ArborEdgeDefense(AED_HOST, AED_TOKEN,
                                         AED_USER, AED_PASS)
        req_data = {
            'details': 1,
        }
        server_resp_data = {
            "errors": [
                {
                    "code": "exceptionField",
                    "field": "CalledProcessError",
                    "message": ("Command '['ahsm_tool', '--cert_lookup', "
                                + "'--cu', u'arbor_cu', '--cu_pass', u'arbo"
                                + "r', '--brief_pub']' returned non-zero ex"
                                + "it status 22"),
                },
            ],
            "message": "An exception has occured",
        }
        mresp = MagicMock()
        mresp.status_code = 500
        mresp.json = Mock(return_value=server_resp_data)
        mget.return_value = mresp
        with self.assertRaises(aedkeyman.ArborEdgeDefenseException):
            aed.list_keys()
        mget.assert_called_with(url=BASE_URL + 'v2/hsm/certificates/',
                                headers=HEADERS, params=req_data,
                                verify=True)

    @patch('aedkeyman.aed.requests.delete')
    def test_delete_key_success(self, mdel):
        aed = aedkeyman.ArborEdgeDefense(AED_HOST, AED_TOKEN,
                                         AED_USER, AED_PASS)
        mresp = MagicMock()
        mresp.status_code = 204
        mresp.json = Mock(return_value=None)
        mdel.return_value = mresp
        aed.delete_key('newrsa')
        mdel.assert_called_with(url=BASE_URL + 'v2/hsm/certificates/newrsa',
                                headers=HEADERS, verify=True)

    @patch('aedkeyman.aed.requests.delete')
    def test_delete_key_fail(self, mdel):
        aed = aedkeyman.ArborEdgeDefense(AED_HOST, AED_TOKEN,
                                         AED_USER, AED_PASS)
        expected_rdata = {
            "errors": [
                {
                    "code": "notFound",
                    "field": "test",
                    "message": "The resource \"test\" could not be found.",
                },
            ],
            "message": "Resource Not Found",
        }
        mresp = MagicMock()
        mresp.status_code = 404
        mresp.json = Mock(return_value=expected_rdata)
        mdel.return_value = mresp
        with self.assertRaises(aedkeyman.ArborEdgeDefenseException):
            aed.delete_key('test')

        mdel.assert_called_with(url=BASE_URL + 'v2/hsm/certificates/test',
                                headers=HEADERS, verify=True)


if __name__ == '__main__':
    unittest.main()
