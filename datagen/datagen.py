#!/usr/bin/env python

# TODO make imports modular based on cli args
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.utils import set_id_namespace as set_stix_id_namespace
from cybox.utils import Namespace
from cybox.utils import set_id_namespace as set_cybox_id_namespace
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.common import Hash
import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages_11 as tm11
from libtaxii.constants import *
import libtaxii.messages_10 as tm10
import datetime
from dateutil.tz import tzutc
import StringIO
import sys
import lxml.etree
from random import randint
from struct import pack
from socket import inet_ntoa
from docopt import docopt
import yaml
import requests
import json
import uuid
import random
import time
import os.path
import pytz
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
import ssdeep

__version__ = '0.1'
app_path = os.path.split(os.path.abspath(__file__))[0]
default_config = os.path.join(app_path, 'data', 'config.yaml')
datatypes = ['ip', 'domain', 'filehash', 'email', 'mixed']
datagen_targets = ['edge', 'crits']

# TODO: add the ability to specify sample data count via cli

__doc__ = '''datagen.py: inject randomly generated sample data in Soltra Edge and MITRE CRITs

Usage:
    datagen.py --inject --type=TYPE --datatype=DATATYPE --target=TARGET [--config=CONFIG] [--count=COUNT]
    datagen.py --list-targets [--config=CONFIG]
    datagen.py --list-types [--config=CONFIG]
    datagen.py --list-datatypes [--config=CONFIG]

    datagen.py --help
    datagen.py --version


Options:
    -C CONFIG --config=CONFIG         Specify config file to use [default: %s].
    -c count --count=COUNT            Specify how many indicators to push (overrides whatever's in config.yaml)
    -d DATATYPE --datatype=DATATYPE   Specify datatype to inject - must be one of %s [default: mixed].
    -t TYPE --type=TYPE               Specify target type - must be one of %s [default: edge].
    -h --help                         Show this screen.
    -V --version                      Show version.
    TARGET...                         Specify host defined in config.yaml

Please report bugs to support@soltra.com
''' % (default_config, ', '.join(datatypes), ', '.join(datagen_targets))


def nowutcmin():
    """time now, but only minute-precision"""
    return datetime.datetime.utcnow().replace(second=0,microsecond=0).replace(tzinfo=pytz.utc)

def epoch_start():
    '''it was the best of times, it was the worst of times...'''
    return datetime.datetime.utcfromtimestamp(0).replace(tzinfo=pytz.utc)


def parse_config(file_):
    '''parse a yaml config file'''
    try:
        return(yaml.safe_load(file(file_, 'r')))
    except yaml.YAMLError:
        print('error parsing yaml file: %s; check your syntax!' % file_)
        exit()

        
def load_tlds(config):
    '''read in icaan tlds file and return a list'''
    file_ = config['datagen']['canonical_tlds']
    tlds_file = open(file_)
    tlds = list()
    for line in tlds_file:
        if not line.startswith('#'):
            tlds.append(line.strip().lower())
    tlds_file.close()
    return(tlds)


def generate_random_hashes():
    '''generate random hashes to simulate a cybox file object'''
    val = str(uuid.uuid4())
    hashes = dict()
    hashes['md5'] = md5(val).hexdigest()
    hashes['sha1'] = sha1(val).hexdigest()
    hashes['sha224'] = sha224(val).hexdigest()
    hashes['sha256'] = sha256(val).hexdigest()
    hashes['sha384'] = sha384(val).hexdigest()
    hashes['sha512'] = sha512(val).hexdigest()
    hashes['ssdeep'] = ssdeep.hash(val)
    return(hashes)
    

def generate_random_domain(config):
    '''generate a random domain name by pairing a random uuid with a random tld'''
    domain = str(uuid.uuid4())
    tld = config['datagen']['tlds'][random.randint(0, len(config['datagen']['tlds']) - 1)]
    domain += '.%s' % tld
    return(domain)


def generate_random_ip_address():
    '''generate a random ip address
    (this will sometimes naively return things like 255.255.255.255)'''
    random_ip = inet_ntoa(pack('>I', randint(1, 0xffffffff)))
    return(random_ip)


def get_crits_api_base_url(config, target):
    '''assemble base url for crits api'''
    url=str()
    if config['crits']['sites'][target]['api']['ssl']:
        url += 'https://'
    else:
        url += 'http://'
    url += config['crits']['sites'][target]['host']
    url += ':' + str(config['crits']['sites'][target]['api']['port'])
    url += config['crits']['sites'][target]['api']['path']
    return(url)


def gen_stix_sample(config, target=None, datatype=None, title='random test data', description='random test data', package_intents='Indicators - Watchlist', tlp_color='WHITE'):
    '''generate sample stix data comprised of indicator_count indicators of type datatype'''
    # setup the xmlns...
    set_stix_id_namespace({config['edge']['sites'][target]['stix']['xmlns_url']: config['edge']['sites'][target]['stix']['xmlns_name']})
    set_cybox_id_namespace(Namespace(config['edge']['sites'][target]['stix']['xmlns_url'], config['edge']['sites'][target]['stix']['xmlns_name']))
    # construct a stix package...
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.title = title
    stix_header.description = description
    stix_header.package_intents = package_intents
    marking = MarkingSpecification()
    marking.controlled_structure = '../../../../descendant-or-self::node()'
    tlp_marking = TLPMarkingStructure()
    tlp_marking.color = tlp_color
    marking.marking_structures.append(tlp_marking)
    stix_package.stix_header = stix_header
    stix_package.stix_header.handling = Marking()
    stix_package.stix_header.handling.add_marking(marking)
    #...and stuff it full of random sample data :-)
    if datatype == 'ip':
        indicator = Indicator(title='IP Address for known C2 Channel')
        indicator.add_indicator_type('IP Watchlist')
        addr = Address(address_value=generate_random_ip_address(), category=Address.CAT_IPV4)
        addr.condition = 'Equals'
        indicator.add_observable(addr)
        stix_package.add_indicator(indicator)
    elif datatype == 'domain':
        indicator = Indicator(title='A Very Bad [tm] Domain')
        indicator.add_indicator_type('Domain Watchlist')
        domain = DomainName()
        domain.type_ = 'FQDN'
        domain.value = generate_random_domain(config)
        domain.condition = 'Equals'
        indicator.add_observable(domain)
        stix_package.add_indicator(indicator)
    elif datatype == 'filehash':
        indicator = Indicator(title='A Very Bad [tm] Filehash')
        indicator.add_indicator_type('File Hash Watchlist')
        file_object = File()
        file_object.file_name = str(uuid.uuid4()) + '.exe'
        hashes = generate_random_hashes()
        for hash in hashes.keys():
            file_object.add_hash(Hash(hashes[hash], type_=hash.upper()))
            for i in file_object.hashes:
                i.simple_hash_value.condition = "Equals"
        indicator.add_observable(file_object)
        stix_package.add_indicator(indicator)
    elif datatype == 'email':
        pass
        #     indicator = Indicator(title='IP Address for known C2 Channel')
        #     indicator.add_indicator_type('IP Watchlist')
        #     addr = Address(address_value=generate_random_ip_address(), category=Address.CAT_IPV4)
        #     addr.condition = 'Equals'
        #     indicator.add_observable(addr)
        #     stix_package.add_indicator(indicator)
    return(stix_package)


def upload_json_via_crits_api(config, target, endpoint, json):
    '''upload data to crits via api, return object id if successful'''
    url = get_crits_api_base_url(config, target)
    if config['crits']['sites'][target]['api']['allow_self_signed']:
        requests.packages.urllib3.disable_warnings()
    # import pudb; pu.db
    data = {'api_key'       : config['crits']['sites'][target]['api']['key'],
            'username'      : config['crits']['sites'][target]['api']['user'],
            'source'        : config['crits']['sites'][target]['api']['source'],
            'releasability' : [{'name': config['crits']['sites'][target]['api']['source']},]}
    data.update(json)
    if config['crits']['sites'][target]['api']['ssl']:
        r = requests.post(url + endpoint + '/' , data=data, verify=not config['crits']['sites'][target]['api']['allow_self_signed'])
    else:
        r = requests.post(url + endpoint + '/', data=data)
    json_output = r.json()
    result_code = json_output[u'return_code']
    success = True if r.status_code == (200 or 201) and result_code == 0 else False
    id_ = json_output[u'id'] if u'id' in json_output.keys() else None
    return(id_, success)


def upload_stix_via_taxii(config, target, stix_package=None):
    # TODO support proxies
    # TODO support certificate auth
    # TODO add more granular error checks
    # TODO take taxii version from config and use the corresponding 
   #      api
    # import pudb; pu.db
    if stix_package:
        stixroot = lxml.etree.fromstring(stix_package.to_xml())
        client = tc.HttpClient()
        client.setUseHttps(config['edge']['sites'][target]['taxii']['ssl'])
        client.setAuthType(client.AUTH_BASIC)
        client.setAuthCredentials({'username': config['edge']['sites'][target]['taxii']['user'], 'password': config['edge']['sites'][target]['taxii']['pass']})
        message = tm11.InboxMessage(message_id=tm11.generate_message_id())
        content_block = tm11.ContentBlock(
            content_binding = t.CB_STIX_XML_11, # of _101, _11, _111
            content         = stixroot,
        )
        message.destination_collection_names = [config['edge']['sites'][target]['taxii']['collection'],]
        # TODO need to avoid syncing when new data on one side is new
        #      precisely because it was just injected from the other
        #      side
        # TODO need to fix timestamps so they match the original data
        # TODO need to set the xmlns to show the origin (aka,
        #      demo_site_a_crits: https://54.154.28.239)
        message.content_blocks.append(content_block)
        taxii_response = client.callTaxiiService2(config['edge']['sites'][target]['host'], config['edge']['sites'][target]['taxii']['path'], t.VID_TAXII_XML_11, message.to_xml(), port=config['edge']['sites'][target]['taxii']['port'])
        if taxii_response.code != 200 or taxii_response.msg != 'OK':
            success = False
        else:
            success = True
        return(success)


def inject_edge_sample_data(config, target=None, datatype=None):
    '''inject randomly generated sample data into edge target'''
    global datatypes
    if datatype != 'mixed':
        i = 0
        while i < config['edge']['datagen']['indicator_count']:
            stix_package = gen_stix_sample(config, target=target, datatype=datatype)
            upload_stix_via_taxii(config, target, stix_package)
            i += 1
    elif datatype == 'mixed':
        types_ = list()
        types_.extend(datatypes)
        types_.remove('mixed')
        types_.remove('email')
        i = 0
        while i < config['edge']['datagen']['indicator_count']:
            type_ = types_[random.randint(0, len(types_) - 1)]
            stix_package = gen_stix_sample(config, target=target, datatype=type_)
            upload_stix_via_taxii(config, target, stix_package)
            i += 1
            print(i)


def generate_crits_json(config, datatype=None):
    if datatype == 'ip':
        ip = generate_random_ip_address()
        return({'ip': ip, 'ip_type': 'Address - ipv4-addr'})
    elif datatype == 'domain':
        return({'domain': generate_random_domain(config)})
    elif datatype == 'filehash':
        hashes = generate_random_hashes()
        json = {'filename': str(uuid.uuid4()) + '.exe', 'upload_type': 'metadata'}
        for hash in hashes.keys():
            json[hash] = hashes[hash]
        return(json)
    elif datatype == 'email':
        return(None)

    
def inject_crits_sample_data(config, target=None, datatype=None):
    '''inject randomly generated sample data into crits target'''
    endpoint = None
    if datatype == 'ip': endpoint = 'ips'
    elif datatype == 'domain': endpoint = 'domains'
    elif datatype == 'email': endpoint = 'emails'
    elif datatype == 'filehash': endpoint = 'samples'

    if datatype != 'mixed':
        i = 0
        while i < config['crits']['datagen']['indicator_count']:
            (id_, success) = upload_json_via_crits_api(config, target, endpoint, generate_crits_json(config, datatype))
            i += 1
    elif datatype == 'mixed':
        pass
        # types_ = list()
        # types_.extend(datatypes)
        # types_.remove('mixed')
        # types_.remove('email')
        # i = 0
        # while i < config['edge']['datagen']['indicator_count']:
        #     type_ = types_[random.randint(0, len(types_) - 1)]
        #     stix_package = gen_stix_sample(config, datatype=type_)
        #     upload_stix_via_taxii(config, target, stix_package)
        #     i += 1
        #     print(i)


def main():
    args = docopt(__doc__, version=__version__)
    global config_file
    config_file = args['--config']
    config = parse_config(config_file)
    if args['--list-targets']:
        for i in config['crits']['sites']:
            print("{crits:<7} {target:<15} {address:<10}".format (crits='[crits]', target=i, address='(' + config['crits']['sites'][i]['host'] + ')'))
        for i in config['edge']['sites']:
            print("{edge:<7} {target:<15} {address:<10}".format (edge='[edge]', target=i, address='(' + config['edge']['sites'][i]['host'] + ')'))
    elif args['--list-types']:
        for i in datagen_targets:
            print(i)
    elif args['--list-datatypes']:
        for i in datatypes:
            print(i)
    elif args['--inject']:
        if not args['--datatype']:
            args['--datatype'] = 'mixed'
        if args['--count']:
            config['crits']['datagen']['indicator_count'] = args['--count']
        if args['--type'] in datagen_targets:
            if args['--type'] == 'crits' and args['--target'] in config['crits']['sites'].keys():
                # override indicator_count from config file if it's
                # passed via cli
                if args['--count']:
                    config['crits']['datagen']['indicator_count'] = int(args['--count'])
                # read in icann tlds list for datagen use
                config['datagen']['tlds'] = load_tlds(config)
                # TODO modify the inject_*_sample_data functions to
                #      generate a mix of ip addresses, file hashes, urls,
                #      and domain names
                inject_crits_sample_data(config, target=args['--target'], datatype=args['--datatype'])
            elif args['--type'] == 'edge' and args['--target'] in config['edge']['sites'].keys():
                # override indicator_count from config file if it's
                # passed via cli
                if args['--count']:
                    config['edge']['datagen']['indicator_count'] = int(args['--count'])
                # read in icann tlds list for datagen use
                config['datagen']['tlds'] = load_tlds(config)
                inject_edge_sample_data(config, target=args['--target'], datatype=args['--datatype'])


if __name__ == '__main__':
    main()





#
# crits api
# =========
#
# {"actoridentifiers":
#     {"list_endpoint": "/api/v1/actoridentifiers/",
#      "schema": "/api/v1/actoridentifiers/schema/"},
#  "actors":
#   {"list_endpoint": "/api/v1/actors/",
#    "schema": "/api/v1/actors/schema/"},
# "campaigns":
#   {"list_endpoint": "/api/v1/campaigns/",
#    "schema": "/api/v1/campaigns/schema/"},
# "certificates":
#   {"list_endpoint": "/api/v1/certificates/",
#    "schema": "/api/v1/certificates/schema/"},
# "domains":
#   {"list_endpoint": "/api/v1/domains/",
#    "schema": "/api/v1/domains/schema/"},
# "emails":
#   {"list_endpoint": "/api/v1/emails/",
#    "schema": "/api/v1/emails/schema/"},
# "events":
#   {"list_endpoint": "/api/v1/events/",
#    "schema": "/api/v1/events/schema/"},
# "indicator_activity":
#   {"list_endpoint": "/api/v1/indicator_activity/",
#    "schema": "/api/v1/indicator_activity/schema/"},
# "indicators":
#   {"list_endpoint": "/api/v1/indicators/",
#    "schema": "/api/v1/indicators/schema/"},
# "ips":
#   {"list_endpoint": "/api/v1/ips/",
#    "schema": "/api/v1/ips/schema/"},
# "objects":
#   {"list_endpoint": "/api/v1/objects/",
#    "schema": "/api/v1/objects/schema/"},
# "pcaps":
#   {"list_endpoint": "/api/v1/pcaps/",
#    "schema": "/api/v1/pcaps/schema/"},
# "raw_data":
#   {"list_endpoint": "/api/v1/raw_data/",
#    "schema": "/api/v1/raw_data/schema/"},
# "relationships":
#   {"list_endpoint": "/api/v1/relationships/",
#    "schema": "/api/v1/relationships/schema/"},
# "samples":
#   {"list_endpoint": "/api/v1/samples/",
#    "schema": "/api/v1/samples/schema/"},
# "screenshots":
#   {"list_endpoint": "/api/v1/screenshots/",
#    "schema": "/api/v1/screenshots/schema/"},
# "services":
#   {"list_endpoint": "/api/v1/services/",
#    "schema": "/api/v1/services/schema/"},
# "standards":
#   {"list_endpoint": "/api/v1/standards/",
#    "schema": "/api/v1/standards/schema/"},
# "targets":
#   {"list_endpoint": "/api/v1/targets/",
#    "schema": "/api/v1/targets/schema/"},
# "whois":
# {"list_endpoint": "/api/v1/whois/",
#  "schema": "/api/v1/whois/schema/"}}
