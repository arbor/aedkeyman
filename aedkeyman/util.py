# Copyright (c) 2019 NETSCOUT Systems, Inc.

"""Miscellaneous helpers."""

import base64
import binascii
import subprocess

import asn1

skey_to_openssl_ecnames = {
    "SecP192K1": "secp192k1",
    "SecP224K1": "secp224k1",
    "SecP256K1": "secp256k1",
    "NistP192": "prime192v1",
    "NistP224": "secp224r1",
    "NistP256": "prime256v1",
    "NistP384": "secp384r1",
    "NistP521": "secp521r1",
}


def get_ec_pem(skey_ecname):
    """Given a curve name from SmartKey return a PEM string."""
    oname = skey_to_openssl_ecnames[skey_ecname]

    output = subprocess.check_output(["openssl", "ecparam", "-name", oname])

    return output.decode("ascii").strip()


def _asn1_find_first_bitstring(instream):
    """Traverse decoder stream and Return the first BitString."""
    value = None
    while not instream.eof():
        tag = instream.peek()
        if tag.typ == asn1.Types.Primitive:
            tag, value = instream.read()
            if tag.nr == asn1.Numbers.BitString:
                break
        elif tag.typ == asn1.Types.Constructed:
            instream.enter()
            value = _asn1_find_first_bitstring(instream)
            instream.leave()

    return value


def pkcs8_to_pub(blob):
    """
    Return the first bitstring given a body of text from PKCS#8.

    This has the effect of removing the version and algorithm ID
    so we are left with just the public key.
    """
    decoder = asn1.Decoder()
    decoder.start(base64.b64decode(blob))
    firstbs = _asn1_find_first_bitstring(decoder)

    pub = binascii.b2a_base64(firstbs[1:]).rstrip()
    return pub.decode("ascii")


def wrap_text_begin_end(title, body):
    """Wrap a block of text with BEGIN and END for PEM formatting."""
    return (
        "-----BEGIN %s-----\n" % (title,)
        + body
        + "\n-----END %s-----\n" % (title,)
    )
