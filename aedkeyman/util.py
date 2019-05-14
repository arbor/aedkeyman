#
# Copyright (c) 2019 NETSCOUT Systems, Inc.
# All rights reserved.  Proprietary and confidential.
#

""" ASN1 Utilities
"""

import asn1
import base64
import binascii


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
