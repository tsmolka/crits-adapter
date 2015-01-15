#!/usr/bin/env python2.7

import os.path
from docopt import docopt
import random
from sys import path as python_path
python_path.append('./lib_')
import datagen_
import yaml
import util_

header_bits = dict()
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
i = 0
for key_ in header_map.keys():
    header_bits[key_] = list()
while i < 5000:
    msg = datagen_.get_random_spam_msg()
    for key_ in header_map.keys():
        val = msg.get(key_, None)
        if val:
            val.replace('\r\n', '\n')
            val.strip()
            if val not in header_bits[key_]:
                header_bits[key_].append(val)
    i += 1
file_ = file('header_bits.yaml', 'w')
yaml.dump(header_bits, file_, default_flow_style=False)
file_.close()
