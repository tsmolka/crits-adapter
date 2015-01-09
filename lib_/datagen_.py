#!/usr/bin/env python2.7

from email.parser import Parser as email_parser
import os.path
import random
import uuid
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
from socket import inet_ntoa
import yaml
from struct import pack
import ssdeep


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


def load_mail_header_bits(config):
    return(yaml.load(file(config['datagen']['email_header_samples'], 'r')))


def get_random_spam_msg(config):
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
    msg = dict()
    for key_ in header_map.keys():
        if key_ in config['datagen']['email_headers'].keys():
            msg[key_] = random.choice(config['datagen']['email_headers'][key_])
    return(msg)
    

def get_email_payload(msg):
    val = None
    # msg has no body
    if not hasattr(msg, 'get_content_maintype'): return(val)
    type_ = msg.get_content_maintype()
    if type_ == 'multipart':
        # msg has no body
        if not hasattr(msg, 'get_payload'): return(val)
        for part in msg.get_payload():
            # probably this is a malformed msg
            if not hasattr(part, 'get_content_type_'): continue
            if part.get_content_type_() == 'text':
                val = part.get_payload()
            elif type_ == 'text':
                val = msg.get_payload()
    return(val)


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
    random_ip = inet_ntoa(pack('>I', random.randint(1, 0xffffffff)))
    return(random_ip)
