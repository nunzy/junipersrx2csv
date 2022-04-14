#!/usr/bin/env python

# author    daniel sargent <dan@nunzy.me.uk>
# created   2022-04-14
# updated   2022-04-14
# url       github.com/nunzy/junipersrx2csv

import argparse
import getpass
import sys
import requests
import json
from netaddr import IPAddress
from lxml import etree
from jnpr.junos import Device
from jnpr.junos.exception import ConnectError
from jnpr.junos.utils.start_shell import StartShell

# disable warnings for insecure connections
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# items
item_types = ['interfaces', 'policies', 'nat', 'zones', 'ike', 'ipsec', 'address-book', 'applications']

def main():
    # build a parser, set arguments, parse the input
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--firewall',             help='Firewall', required=True)
    parser.add_argument('-u', '--user',                 help='Username', required=True)
    parser.add_argument('-ri', '--routing-instance',    help='VRF', required=True)
    parser.add_argument('-i', '--item',                 help='Item', default='all')
    parser.add_argument('-t', '--translate',            help='Include translation of IP objects', action='store_true')
    parser.add_argument('-o', '--outfile',              help='Output file')
    parser.add_argument('-z', '--zones',                help='Firewall zones', default='all', nargs='+')
    args = parser.parse_args()

    print(args)

    # check item type
    if args.item == 'all':
        print(f'Retriving all data')
    elif args.item not in item_types:
        print(f'Please choose a valid item type: {", ".join(map(str, item_types))}')
        sys.exit(1)

    # use a hidden password entry
    password = getpass.getpass()

    # connect and authenticate
    print(f'Connecting to {args.routing_instance}@{args.firewall} as {args.user}')
    dev = Device(host=args.firewall, user=args.user, passwd=password)
    try:
        dev.open()
    except ConnectError as err:
        print("Cannot connect to device: {0}".format(err))
        sys.exit(1)
    except Exception as err:
        print(err)
        sys.exit(1)

    ss = StartShell(dev)

    # build a translation table if required
    if args.translate:
        print('Building lookup tables')
        # add addresses to the local lookup table

    # split routing-instance into customer-crm and uuid stings
    customercrm_uuid = args.routing_instance.rsplit("-", 1)

    for from_zone in args.zones:
        security_zone_from = customercrm_uuid[0] + "-" + from_zone + "-" + customercrm_uuid[1]
        for to_zone in args.zones:
            security_zone_to = customercrm_uuid[0] + "-" + to_zone + "-" + customercrm_uuid[1]
            xml_filter = "<security><policies><policy><from-zone-name>" + security_zone_from + "</from-zone-name><to-zone-name>" + security_zone_to + "</to-zone-name></policy></policies></security>"
            try:
                policies_data = dev.rpc.get_config(
                    filter_xml=etree.XML(xml_filter),
                    options={'format': 'json'})
                #print(policies_data)
            except:
                print(f'Security policies {security_zone_from} to {security_zone_to} not configured.')

    # logout to prevent stale sessions
    print(f'Logging out of firewall')
    dev.close()

    print(f'Done!')


if __name__ == "__main__":
   main()
