#
# Copyright (c) 2019 NETSCOUT Systems, Inc.
# All rights reserved.  Proprietary and confidential.
#

"""
Manage keys on Arbor Edge Defense and between third parties.
"""

import argparse
from datetime import timedelta
import getpass
import logging
import os
import sys
import subprocess

from aedkeyman import (MissingConfigException,
                       ArborEdgeDefense, ArborEdgeDefenseException,
                       SmartKey, SmartKeyException,
                       SmartKeyNeedsAuthException,
                       SmartKeyNeedsAcctSelectException,
                       SmartKeyAuthUserException,
                       pkcs8_to_pub)


# How much to indent hierarchical output
indent_step = 2

# Global count of the number of errors that have occurred.
error_count = 0

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

elliptic_curves = skey_to_openssl_ecnames.keys()


def get_elliptic_curves():
    return elliptic_curves


def get_ec_pem(skey_ecname):
    """
    Given a curve name from SmartKey return a PEM blob (including BEGIN
    and END)
    """
    oname = skey_to_openssl_ecnames[skey_ecname]

    output = subprocess.check_output(['openssl', 'ecparam', '-name', oname])

    return output.strip()


def get_skey_kwargs(args):
    """
    Return optional keyword arguments for aedkeyman.SmartKey.__init__()
    """
    #
    # For development purposes we allow the API KEY to be set in the
    # environment. This will authenticate as an application and avoid prompting
    # the user.
    #
    kwargs = {
        'apikey': os.getenv('SKEY_API_KEY')
    }
    return kwargs


def get_aed_args(args):
    """
    Return mandatory arguments for aedkeyman.aed.__init__()
    """
    #
    # For development purposes we allow the API KEY to be set in the
    # environment. This will authenticate as an application and avoid prompting
    # the user.
    #
    hostname = os.getenv('AED_HOST')
    if hostname is None:
        raise MissingConfigException("Set AED_HOST to the hostname " +
                                     "of Arbor AED")
    token = os.getenv('AED_TOKEN')
    if token is None:
        raise MissingConfigException("Set AED_TOKEN to the API TOKEN" +
                                     "for Arbor AED")

    hsm_user = os.getenv('AED_HSM_USER')
    if hsm_user is None:
        raise MissingConfigException("Set AED_HSM_USER to the HSM crypto" +
                                     "user for Arbor AED")

    hsm_pass = os.getenv('AED_HSM_PASS')
    if hsm_pass is None:
        raise MissingConfigException("Set AED_HSM_PASS to the HSM crypto" +
                                     "user password for Arbor AED")

    if os.getenv('AED_DISABLE_CERT_VERIFY', 'false') == 'true':
        disable_cert_verify = True
    else:
        disable_cert_verify = False

    return (hostname, token, hsm_user, hsm_pass, disable_cert_verify)


def cmd_skey_login(args):
    """
    Create a new session by authenticating as a user.
    """
    if args.username is None:
        print "Username: ",
        username = sys.stdin.readline().strip()
    else:
        username = args.username

    if args.password is None:
        password = getpass.getpass()
    else:
        password = args.password

    ska = SmartKey(**get_skey_kwargs(args))
    ttl = ska.auth_user(username, password, save=True)

    print ("Session will expire in %s. Use the 'skey-logout' command to " +
           "terminate it sooner.") % (timedelta(seconds=ttl),)

    # Select the account to use. Sometimes this is required.
    # TODO: Make auto_account_id the default behavior?
    if args.auto_account_id:
        accounts = ska.list_accounts()
        if len(accounts) > 1:
            logging.warn("Multiple accounts available, using the first one")
        acid = accounts[0]['acct_id']
        logging.debug("Selecting account %s" % acid)
        output_and_exit(ska.select_account(acid))

    if args.account_id is not None:
        logging.debug("Selecting account %s" % args.account_id)
        output_and_exit(ska.select_account(args.account_id))


def cmd_skey_logout(args):
    """
    Terminate a session. This invalidates the saved token.
    """
    ska = SmartKey(**get_skey_kwargs(args))
    output_and_exit(ska.terminate_session())


def cmd_skey_gen_ec_key(args):
    ska = SmartKey(**get_skey_kwargs(args))
    output_and_exit(ska.generate_ec_key(args.name, args.curve,
                                        args.group_id, args.desc))


def cmd_skey_show_key(args):
    ska = SmartKey(**get_skey_kwargs(args))
    output_and_exit(ska.get_key(args.kid))


def cmd_skey_delete_key(args):
    ska = SmartKey(**get_skey_kwargs(args))
    name = None

    if args.update_aed:
        aed = ArborEdgeDefense(*get_aed_args(args))

    if args.all:
        ska_keys = ska.list_keys()
        for key in ska_keys:
            name = key['name']
            kid = key['kid']
            try:
                output_and_exit(ska.delete_key(kid))
            except SmartKeyException, exc:
                msg = "Failed to delete '%s' on SmartKey: %s" % (name, exc)
                output_error(msg)
            if args.update_aed:
                try:
                    aed.delete_key(name)
                except ArborEdgeDefenseException, exc:
                    msg = "Failed to delete '%s' on AED: %s" % (name, exc)
                    output_error(msg)
    elif args.kid:
        if args.update_aed:
            msg = ("With --update-aed the key must be specified by name" %
                   (name,))
            output_and_exit(msg, error=True)
        else:
            output_and_exit(ska.delete_key(args.kid))

    elif args.name:
        name = args.name
        kid = name_to_skey_id(ska, args.name)
        if kid is None:
            output_and_exit("No key '%s' found" % (name,), error=True)
        try:
            ska.delete_key(kid)
        except SmartKeyException, exc:
            msg = "Failed to delete '%s' on SmartKey: %s" % (name, exc)
            output_and_exit(msg, error=True)
        else:
            if args.update_aed:
                try:
                    aed.delete_key(name)
                except ArborEdgeDefenseException, exc:
                    msg = "Failed to delete '%s' on AED: %s" % (name, exc)
                    output_error(msg)
    else:
        output_error("Specify '--name', '--kid', or '--all'")


def cmd_skey_export_key(args):
    ska = SmartKey(**get_skey_kwargs(args))

    data = ska.export_key(args.kid)
    if data['obj_type'] == 'RSA':
        pub = wrap_text_begin_end("RSA PUBLIC KEY", data['pub_key'])
        priv = wrap_text_begin_end("RSA PRIVATE KEY", data['value'])
        blob = "\n".join([pub, priv])
    elif data['obj_type'] == 'EC':
        pub = wrap_text_begin_end("PUBLIC KEY", data['pub_key'])
        priv = wrap_text_begin_end("EC PRIVATE KEY", data['value'])
        ecparams = get_ec_pem(data['elliptic_curve'])
        blob = "\n".join([ecparams, priv, pub])

    if args.out_file is not None:
        with open(args.out_file, "w") as outfile:
            outfile.write(blob)

    if args.out_pub_file is not None:
        with open(args.out_pub_file, "w") as outfile:
            outfile.write(pub)

    if args.out_priv_file is not None:
        with open(args.out_priv_file, "w") as outfile:
            outfile.write(priv)

    # If there is any output being written to a file, suppress
    # normal program output
    if (not args.out_file and not args.out_priv_file and
            not args.out_pub_file):
        print blob


def cmd_skey_list_accounts(args):
    ska = SmartKey(**get_skey_kwargs(args))
    output_and_exit(ska.list_accounts())


def cmd_skey_list_groups(args):
    ska = SmartKey(**get_skey_kwargs(args))
    output_and_exit(ska.list_groups())


def name_to_skey_id(ska, name):
    data = ska.list_keys(name=name)
    if len(data) > 0:
        return data[0]['kid']
    else:
        return None


def cmd_skey_name_to_kid(args):
    ska = SmartKey(**get_skey_kwargs(args))
    kid = name_to_skey_id(ska, args.name)
    if kid is None:
        output_and_exit("No key '%s' found" % (args.name,), error=True)
    else:
        print kid


def cmd_aed_list_keys(args):
    eargs = get_aed_args(args)
    aed = ArborEdgeDefense(*eargs)
    output_and_exit(aed.list_keys())


def cmd_aed_import_ec_key(args):
    if args.in_file is not None:
        with open(args.in_file) as infile:
            blob = infile.read()
    else:
        print "Enter EC Parameters and press ^d when done"
        params = sys.stdin.read()
        print "Enter EC Private Key and press ^d when done"
        priv = sys.stdin.read()
        paramstext = wrap_text_begin_end("EC PARAMETERS", params.strip())
        privtext = wrap_text_begin_end("EC PRIVATE KEY", priv.strip())
        blob = "\n".join([paramstext, privtext])
        print blob

    aed = ArborEdgeDefense(*get_aed_args(args))
    output_and_exit(aed.import_key(args.name, blob))


def cmd_aed_import_rsa_key(args):
    if args.in_priv_file is not None:
        with open(args.in_priv_file) as infile:
            priv = infile.read().strip()
    else:
        print "Enter RSA Private Key and press ^d when done"
        priv = sys.stdin.read().strip()

    aed = ArborEdgeDefense(*get_aed_args(args))
    output_and_exit(aed.import_key(args.name, priv))


def cmd_aed_delete_key(args):
    aed = ArborEdgeDefense(*get_aed_args(args))

    if args.all:
        aed_keys = aed.list_keys()

        for akey in aed_keys:
            name = akey['name']
            try:
                aed.delete_key(name)
            except ArborEdgeDefenseException, exc:
                msg = "Failed to delete '%s' on AED: %s" % (name, exc)
                output_error(msg)
    elif args.name is not None:
            try:
                aed.delete_key(args.name)
            except ArborEdgeDefenseException, exc:
                msg = "Failed to delete '%s' on AED: %s" % (args.name, exc)
                output_error(msg)


def cmd_skey_gen_rsa_key(args):
    ska = SmartKey(**get_skey_kwargs(args))
    data = ska.generate_rsa_key(args.name, args.size, args.desc,
                                args.group_id)
    kid = data
    try:
        data = ska.export_key(kid)
    except SmartKeyException as exc:
        # Generate was successful but we failed to export
        try:
            ska.delete_key(kid)
        except SmartKeyException as dexc:
            # Failed to export and delete
            # output original so we see the errors in order
            output_error(str(exc))
            output_error("Key '%s' left on SmartKey" % (kid,))
            raise dexc
        else:
            raise exc

    if args.update_aed:
        aed = ArborEdgeDefense(*get_aed_args(args))
        priv = wrap_text_begin_end("RSA PRIVATE KEY", data['value'])
        try:
            aed.import_key(args.name, priv)
        except ArborEdgeDefenseException as exc:
            # Import failed but we generated the key
            try:
                ska.delete_key(kid)
            except SmartKeyException as dexc:
                # Failed to export and delete
                # output original so we see the errors in order
                output_error(str(exc))
                # TODO: test ordering/error formatting here
                output_error("Key %s left on SmartKey" % (kid,))
                raise dexc
            else:
                raise exc


def cmd_skey_list_keys(args):
    aed = ArborEdgeDefense(*get_aed_args(args))
    ska = SmartKey(**get_skey_kwargs(args))
    aed_keys = aed.list_keys()
    ska_keys = ska.list_keys()
    akeym = {}
    skeym = {}

    if args.debug:
        output_and_exit(ska_keys)

    for key in ska_keys:
        skeym[key['name']] = key
    for key in aed_keys:
        akeym[key['name']] = key

    # TODO: this doesn't support when you have multiple keys with the same
    # name in SmartKey.
    snames = set(skey['name'] for skey in ska_keys)
    anames = set(akey['name'] for akey in aed_keys)
    allnames = sorted(snames.union(anames))
    print ("Name                                               Type" +
           "         SmartKey AED")
    for name in allnames:
        inskey = 'NO'
        inakey = 'NO'
        if name in snames:
            inskey = 'YES'
            ktype = skeym[name]['obj_type']
            if ktype == 'CERTIFICATE':
                ktype = skeym[name]['obj_type']
                # See if there is a stored public key from AED that matches
                # for aedkey in aed_keys:
                #    if aedkey
        if name in anames:
            inakey = 'YES'
            ktype = akeym[name]['type']

        fname = "%s %s" % (name, '.' * (49 - len(name)))
        print "%-50s %-12s %-3s      %s" % (fname, ktype, inskey, inakey)


def cmd_skey_sync_keys(args):
    """
    Push the keys from the SmartKey HSM to the AED HSM.
    """
    aed = ArborEdgeDefense(*get_aed_args(args))
    ska = SmartKey(**get_skey_kwargs(args))
    aed_keys = aed.list_keys()
    ska_keys = ska.list_keys()

    aedpubs = set([akey['public'] for akey in aed_keys])
    for key in ska_keys:
        name = key['name']
        ktype = key['obj_type']
        # Skip non-RSA or EC types such as CERTIFICATE and DES3 types
        if ktype != 'RSA' and ktype != 'EC':
            continue

        # Skip keys that lack the required permissions (key_ops)
        key_ops = key['key_ops']
        if ('EXPORT' not in key_ops) or ('APPMANAGEABLE' not in key_ops):
            logging.debug("key %s does not have the necessary permissions" %
                          (name,))
            continue

        pub = pkcs8_to_pub(key['pub_key'])
        if pub in aedpubs:
            logging.debug("key %s already on AED" % (name,))
            continue
        else:
            logging.debug("key %s not on AED" % (name,))

        kid = key['kid']
        if ktype == 'RSA':
            try:
                data = ska.export_key(kid)
            except SmartKeyException, exc:
                msg = "%s (%s)" % (exc, name)
                output_error(msg)
                continue

            if pub != data['pub_key']:
                logging.warn("Public mismatch during export on key %s" %
                             name)

            priv = wrap_text_begin_end("RSA PRIVATE KEY", data['value'])
        elif ktype == 'EC':
            try:
                data = ska.export_key(kid)
            except SmartKeyException, exc:
                msg = "%s (%s)" % (exc, name)
                output_error(msg)
                continue

            curve_name = key['elliptic_curve']
            ecparams = get_ec_pem(curve_name)
            value = wrap_text_begin_end("EC PRIVATE KEY", data['value'])
            priv = "\n".join((ecparams, value))

        try:
            aed.import_key(name, priv)
        except ArborEdgeDefenseException, exc:
            msg = "Failed to import '%s' on AED: %s" % (name, exc)
            output_error(msg)
            continue


def wrap_text_begin_end(title, body):
    """
    Helper to wrap a block of text with BEGIN and END for PEM formatting.
    """
    return ("-----BEGIN %s-----\n" % (title,) + body +
            "\n-----END %s-----" % (title,))


def output_and_exit(data, error=False):
    output(data, error)
    exit(error)


def output_error(data):
    """
    Given the data returned from a SmartKey or ArborEdgeDefense, print data to
    stderr.
    """
    output(data, error=True)


def output(data, error=False, indent=0):
    """
    Given the data returned from a SmartKey or ArborEdgeDefense, print data to
    stdout/stderr. This is a generic output handler intended to provide minimal
    formatting for whatever type of data is returned.
    """
    if error:
        global error_count

        error_count += 1

        if data is not None:
            if isinstance(data, tuple) or isinstance(data, list):
                if len(data) > 1:
                    print >>sys.stderr, "Error: Multiple errors occured"
                    for line in data:
                        print >>sys.stderr, "\t%s" % (line,)
                else:
                    print >>sys.stderr, "Error: %s" % (data[0],)
            else:
                print >>sys.stderr, "Error: %s" % (data,)
    else:
        istr = indent * ' '
        if data is not None:
            if isinstance(data, tuple) or isinstance(data, list):
                if len(data) > 0:
                    # If it's a list of dicts we want to indent each
                    # item more.
                    if isinstance(data[0], dict):
                        for item in data:
                            output(item, error, indent)
                    else:
                        for item in data:
                            output(item, error, indent)
            elif isinstance(data, dict):
                for key in sorted(data):
                    val = data[key]
                    if (isinstance(val, dict) or isinstance(val, tuple) or
                            isinstance(val, list)):
                        print istr + "%s:" % (key,)
                        output(val, error, indent + indent_step)
                    else:
                        print istr + "%s: %s" % (key, val)
                # Print a new line to help separate the first level of
                # objects we are displaying.
                if indent == 0:
                    print
            else:
                print istr + data


def exit(error):
    """
    Exit with the appropriate status based on if there is currently an error
    or if there was an error.
    """
    global error_count

    sys.exit(1 if error or error_count > 0 else 0)


def get_handler(name):
    """
    Given a command name, return function to handle it.

    Handlers are all prefixed with cmd_ and named after the command with
    hyphens changing to underscores, i.e. aed-list-keys = cmd_aed_list_keys.
    """
    fname = "cmd_" + name.lower().replace('-', '_')
    handler = globals().get(fname, None)

    return handler


def invoke_handler(progname, args):
    """
    Invoke the command handler for the parsed arguments.
    """
    try:
        args.func(args)
    except SmartKeyAuthUserException as exc:
        output_and_exit(exc, error=True)
    except SmartKeyNeedsAcctSelectException as exc:
        msg = ("%s. Try running '%s skey-login' and including account-id." %
               (exc, progname))
        output_and_exit(msg, error=True)
    except SmartKeyNeedsAuthException as exc:
        # XXX: Sometimes omitting an account-id causes a generic NeedsAuth
        # so always suggest including account-id for now.
        msg = ("%s. Try running '%s skey-login' and including account-id." %
               (exc, progname))
        output_and_exit(msg, error=True)
    except MissingConfigException as exc:
        output_and_exit(exc, error=True)
    except SmartKeyException as exc:
        output_and_exit(exc, error=True)
    except ArborEdgeDefenseException as exc:
        output_and_exit(exc, error=True)


def main():
    """
    Entry
    """

    # -v enable additional messages, without this silence is golden
    # -vv enable debug messages like pretty print data used in transactions
    # -vvv like above but also include dump all data sent and received
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verbose', '-v', action='count', default=0,
                        help="increase log level)")
    subparsers = parser.add_subparsers(title='subcommands')

    def register_cmd(name, help=None):
        """
        Register a top-level command.
        """
        newp = subparsers.add_parser(name, help=help)
        newp.set_defaults(func=get_handler(name))
        return newp

    #
    # Commands for managing keys on AED
    #
    subp = register_cmd('aed-delete-key', help="delete a key on AED")
    groupp = subp.add_mutually_exclusive_group()
    groupp.add_argument('--name', type=str, metavar='STRING')
    groupp.add_argument('--all', action='store_true')

    subp = register_cmd('aed-import-ec-key', help="Push an RSA key")
    subp.add_argument('name', type=str, help="name/label for the key")
    subp.add_argument('--in-file', type=str, metavar='FILE',
                      help="file with private key and params in PEM format")

    subp = register_cmd('aed-import-rsa-key', help="Push an RSA key")
    subp.add_argument('name', type=str, help="name/label for the key")
    subp.add_argument('--in-priv-file', type=str, metavar='FILE',
                      help="file containing private key in PEM format")

    subp = register_cmd('aed-list-keys', help="list keys on AED")

    #
    # Commands for managing keys with SmartKey
    #
    subp = register_cmd('skey-delete-key', 'delete a key from SmartKey')
    subp.add_argument('--update-aed', action='store_true',
                      help="also delete the key on AED")
    groupp = subp.add_mutually_exclusive_group()
    groupp.add_argument('--name', type=str, metavar='STRING')
    groupp.add_argument('--kid', type=str, metavar='UUID')
    groupp.add_argument('--all', action='store_true')

    subp = register_cmd('skey-export-key',
                        help="export a security object from SmartKey")
    subp.add_argument('kid', type=str, metavar='KID')
    subp.add_argument('--out-file', type=str, metavar='FILE',
                      help="File for output in PEM format")
    subp.add_argument('--out-priv-file', type=str, metavar='FILE',
                      help="File for private key output in PEM format")
    # TODO: put ecparams in out-pub-file
    subp.add_argument('--out-pub-file', type=str, metavar='FILE',
                      help="File for public key output in PEM format")
    subp.add_argument('--out-cert-file', type=str, metavar='FILE',
                      help="File for cerficate output in PEM format")

    subp = register_cmd('skey-gen-ec-key',
                        help="generate an EC key on SmartKey")
    subp.add_argument('name', type=str, help="name/label for the key")
    subp.add_argument('curve', type=str,
                      choices=get_elliptic_curves(),
                      help="standardized elliptic curve to use")
    subp.add_argument('--desc', type=str, metavar="STRING",
                      help="description of EC key")
    groupp = subp.add_mutually_exclusive_group()
    groupp.add_argument('--group-id', type=str, metavar='ID',
                        help="id of group the key should belong to")
    # groupp.add_argument('--group-name', type=str, metavar='NAME',
    #                    help="name of group the key should belong to")
    subp.add_argument('--update-aed', action='store_true',
                      help="also push the key to AED")

    subp = register_cmd('skey-gen-rsa-key',
                        help="generate an RSA key on SmartKey")
    subp.add_argument('name', type=str, help="name/label for the key")
    subp.add_argument('--size', type=int, metavar='N', default=4096,
                      help="size of key in bits")
    subp.add_argument('--desc', type=str, metavar="STRING",
                      help="description of RSA key")
    groupp = subp.add_mutually_exclusive_group()
    groupp.add_argument('--group-id', type=str, metavar='ID',
                        help="id of group the key should belong to")
    # groupp.add_argument('--group-name', type=str, metavar='NAME',
    #                    help="name of group the key should belong to")
    subp.add_argument('--out-priv-file', type=str, metavar='FILE',
                      help=("file for private key output in PEM format (for " +
                            " web server)"))
    subp.add_argument('--out-pub-file', type=str, metavar='FILE',
                      help=("file for public key output in PEM format (for " +
                            "CSR)"))
    subp.add_argument('--update-aed', action='store_true',
                      help="also push the key to AED")

    subp = register_cmd('skey-list-accounts', help="list accounts on SmartKey")
    subp = register_cmd('skey-list-groups', help="list groups on SmartKey")

    subp = register_cmd('skey-list-keys',
                        help="list security objects in SmartKey")
    subp.add_argument('--debug', action='store_true',
                      help="list all attributes")

    subp = register_cmd('skey-login',
                        help="authenticate with SmartKey")
    subp.add_argument('--username', type=str, metavar='USERNAME',
                      help="username to login with")
    subp.add_argument('--password', type=str, metavar='PASSWORD',
                      help="password for authentication")
    groupp = subp.add_mutually_exclusive_group()
    groupp.add_argument('--account-id', type=str, metavar='UUID',
                        help="select a specific account ID")
    groupp.add_argument('--auto-account-id', action='store_true',
                        help="")

    subp = register_cmd('skey-logout',
                        help="terminate session with SmartKey")

    subp = register_cmd('skey-name-to-kid', help="show the key ID for a key")
    subp.add_argument('name', type=str, help="name/label for the key")

    subp = register_cmd('skey-show-key', help="show details for a key")
    subp.add_argument('kid', type=str, metavar='KID')

    subp = register_cmd('skey-sync-keys',
                        help="push keys from SmartKey to AED")

    args = parser.parse_args()

    logger = logging.getLogger()

    if args.verbose == 0:
        logger.setLevel(logging.WARN)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    elif args.verbose >= 2:
        logger.setLevel(logging.DEBUG)

    invoke_handler(parser.prog, args)


if __name__ == '__main__':
    main()
