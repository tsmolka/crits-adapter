#!/usr/bin/env python2.7

from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.utils import set_id_namespace as set_stix_id_namespace
from cybox.utils import Namespace
from cybox.utils import set_id_namespace as set_cybox_id_namespace
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage, EmailHeader
from cybox.objects.file_object import File
from cybox.common import Hash
from cybox.core.observable import Observable
from cybox.core import Observables
import os.path
from docopt import docopt
import random
import uuid
from sys import path as python_path
python_path.append('./lib_')
import util_
import datagen_
import crits_
import edge_


__version__ = '0.2'
app_path = os.path.split(os.path.abspath(__file__))[0]
default_config = os.path.join(app_path, 'config.yaml')
datatypes = ['ip', 'domain', 'filehash', 'email', 'mixed']
datagen_targets = ['edge', 'crits']


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
        addr = Address(address_value=datagen_.generate_random_ip_address(), category='ipv4-addr')
        addr.condition = 'Equals'
        stix_package.add_observable(Observable(addr))
    elif datatype == 'domain':
        domain = DomainName()
        domain.type_ = 'FQDN'
        domain.value = datagen_.generate_random_domain(config)
        domain.condition = 'Equals'
        stix_package.add_observable(Observable(domain))
    elif datatype == 'filehash':
        file_object = File()
        file_object.file_name = str(uuid.uuid4()) + '.exe'
        hashes = datagen_.generate_random_hashes()
        for hash in hashes.keys():
            file_object.add_hash(Hash(hashes[hash], type_=hash.upper()))
            for i in file_object.hashes:
                i.simple_hash_value.condition = "Equals"
        stix_package.add_observable(Observable(file_object))
    elif datatype == 'email':
        try:
            msg = datagen_.get_random_spam_msg(config)
            email = EmailMessage()
            email.header = EmailHeader()
            header_map = {'Subject': 'subject', 'To': 'to', 'Cc':
                          'cc', 'Bcc': 'bcc', 'From': 'from_',
                          'Sender': 'sender', 'Date': 'date',
                          'Message-ID': 'message_id', 'Reply-To':
                          'reply_to', 'In-Reply-To': 'in_reply_to',
                          'Content-Type': 'content_type', 'Errors-To':
                          'errors_to', 'Precedence': 'precedence',
                          'Boundary': 'boundary', 'MIME-Version':
                          'mime_version', 'X-Mailer': 'x_mailer',
                          'User-Agent': 'user_agent',
                          'X-Originating-IP': 'x_originating_ip',
                          'X-Priority': 'x_priority'}
            # TODO handle received_lines
            for key in header_map.keys():
                val = msg.get(key, None)
                if val:
                    email.header.__setattr__(header_map[key], val)
                    email.header.__getattribute__(header_map[key]).condition = 'Equals'
            # TODO handle email bodies (it's mostly all there except for
            #      handling weird text encoding problems that were making
            #      libcybox stacktrace)
            # body = get_email_payload(random_spam_msg)
            # if body:
            #     email.raw_body = body
            stix_package.add_observable(Observable(email))
        except:
            return(None)
    return(stix_package)


def inject_edge_sample_data(config, target=None, datatype=None):
    '''inject randomly generated sample data into edge target'''
    global datatypes
    if datatype != 'mixed':
        i = 0
        while i < config['edge']['datagen']['indicator_count']:
            stix_ = gen_stix_sample(config, target=target, datatype=datatype)
            success = edge_.taxii_inbox(config, target, stix_)
            if success:
                i += 1
            else: print('error inboxing edge sample data to %s - exiting!' % target); exit()
    elif datatype == 'mixed':
        types_ = list()
        types_.extend(datatypes)
        types_.remove('mixed')
        i = 0
        while i < config['edge']['datagen']['indicator_count']:
            type_ = types_[random.randint(0, len(types_) - 1)]
            stix_ = gen_stix_sample(config, target=target, datatype=type_)
            success = edge_.taxii_inbox(config, target, stix_)
            if success:
                i += 1
            else: continue


def generate_crits_json(config, datatype=None):
    if datatype == 'ip':
        ip = datagen_.generate_random_ip_address()
        return({'ip': ip, 'ip_type': 'Address - ipv4-addr'})
    elif datatype == 'domain':
        return({'domain': datagen_.generate_random_domain(config)})
    elif datatype == 'filehash':
        hashes = datagen_.generate_random_hashes()
        json = {'filename': str(uuid.uuid4()) + '.exe', 'upload_type': 'metadata'}
        for hash in hashes.keys():
            json[hash] = hashes[hash]
        return(json)
    elif datatype == 'email':
        msg = datagen_.get_random_spam_msg(config)
        json = {'upload_type': 'fields'}
        header_map = {'Subject': 'subject', 'To': 'to', 'Cc': 'cc',
                      'From': 'from_address', 'Sender': 'sender', 'Date':
                      'date', 'Message-ID': 'message_id', 'Reply-To':
                      'reply_to', 'Boundary': 'boundary', 'X-Mailer':
                      'x_mailer', 'X-Originating-IP':
                      'x_originating_ip'}
        for key in header_map.keys():
            val = msg.get(key, None)
            if val:
                if key in ['To', 'Cc']:
                    json[header_map[key]] = [val,]
                else:
                    json[header_map[key]] = val
        return(json)

            
def inject_crits_sample_data(config, target=None, datatype=None):
    '''inject randomly generated sample data into crits target'''
    global datatypes
    endpoint = None
    if datatype == 'ip': endpoint = 'ips'
    elif datatype == 'domain': endpoint = 'domains'
    elif datatype == 'email': endpoint = 'emails'
    elif datatype == 'filehash': endpoint = 'samples'

    if datatype != 'mixed':
        i = 0
        while i < config['crits']['datagen']['indicator_count']:
            (id_, success) = crits_.crits_inbox(config, target, endpoint, generate_crits_json(config, datatype))
            if success:
                i += 1
            else: print('error inboxing crits sample data to %s - exiting!' % target); exit()
    elif datatype == 'mixed':
        types_ = list()
        types_.extend(datatypes)
        types_.remove('mixed')
        i = 0
        while i < config['crits']['datagen']['indicator_count']:
            type_ = types_[random.randint(0, len(types_) - 1)]
            if type_ == 'ip': endpoint = 'ips'
            elif type_ == 'domain': endpoint = 'domains'
            elif type_ == 'email': endpoint = 'emails'
            elif type_ == 'filehash': endpoint = 'samples'
            (id_, success) = crits_.crits_inbox(config, target, endpoint, generate_crits_json(config, type_))
            if success:
                i += 1
            else: continue


def main():
    args = docopt(__doc__, version=__version__)
    global config_file
    config_file = args['--config']
    config = util_.parse_config(config_file)
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
                config['datagen']['tlds'] = datagen_.load_tlds(config)
                # read in email header samples for datagen use
                config['datagen']['email_headers'] = datagen_.load_mail_header_bits(config)
                inject_crits_sample_data(config, target=args['--target'], datatype=args['--datatype'])
            elif args['--type'] == 'edge' and args['--target'] in config['edge']['sites'].keys():
                # override indicator_count from config file if it's
                # passed via cli
                if args['--count']:
                    config['edge']['datagen']['indicator_count'] = int(args['--count'])
                # read in icann tlds list for datagen use
                config['datagen']['tlds'] = datagen_.load_tlds(config)
                # read in email header samples for datagen use
                config['datagen']['email_headers'] = datagen_.load_mail_header_bits(config)
                inject_edge_sample_data(config, target=args['--target'], datatype=args['--datatype'])


if __name__ == '__main__':
    main()
