#
# Copyright (c) 2019 NETSCOUT Systems, Inc.
# All rights reserved.  Proprietary and confidential.
#

""" Misc helpers
"""

import asn1
import base64
import binascii
import subprocess


skey_to_openssl_ecnames = {
    'SecP192K1': 'secp192k1',
    'SecP224K1': 'secp224k1',
    'SecP256K1': 'secp256k1',
    'NistP192': 'prime192v1',
    'NistP224': 'secp224r1',
    'NistP256': 'prime256v1',
    'NistP384': 'secp384r1',
    'NistP521': 'secp521r1',
}


def get_ec_pem(skey_ecname):
    """
    Given a curve name from SmartKey return a PEM blob (including BEGIN
    and END)
    """
    oname = skey_to_openssl_ecnames[skey_ecname]

    output = subprocess.check_output(['openssl', 'ecparam', '-name', oname])

    return output.strip()


def find_first_bitstring(instream):
    """ Traverse an asn1 decoder stream and Return the first
    type that is a BitString.
    """
    value = None
    while not instream.eof():
        tag = instream.peek()
        if tag.typ == asn1.Types.Primitive:
            tag, value = instream.read()
            if tag.nr == asn1.Numbers.BitString:
                break
        elif tag.typ == asn1.Types.Constructed:
            instream.enter()
            value = find_first_bitstring(instream)
            instream.leave()

    return value


def pkcs8_to_pub(blob):
    """ Return the first bitstring in an PKCS#8 blob.
    This has the effect of removing the version and algorithm ID
    so we are left with just the public key.
    """
    decoder = asn1.Decoder()
    decoder.start(base64.b64decode(blob))
    value = find_first_bitstring(decoder)

    return binascii.b2a_base64(value[1:]).rstrip()
