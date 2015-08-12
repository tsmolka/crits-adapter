import unittest

from cybox.core import Observables
from cybox.objects.address_object import Address
from cybox.objects.email_message_object import EmailMessage

from cybox import helper
from cybox.core.observable import Observable

from lib.crits import crits_url, stix_pkg


class TestCrits(unittest.TestCase):
    testing_config = {
        'datagen': {
            'email_header_samples': 'datagen_samples/mail_headers.yaml',
            'canonical_tlds': 'datagen_samples/crits-tlds.txt'},
        'crits': {
            'datagen': {'indicator_count': 100},
            'sites': {
                'localhost': {
                    'host': '127.0.0.1',
                    'api': {
                        'source': 'source',
                        'poll_interval': 30,
                        'releasability': 'releasable',
                        'port': 8080,
                        'ssl': True,
                        'max_results': 1000,
                        'user': 'api_user',
                        'key': '123e4567e8e9e06102ba91ea058283e7644f1a40',
                        'path': '/api/v1/',
                        'attempt_certificate_validation': False,
                        'use_releasability': True},
                    'enabled': True
                }
            }
        },
        'edge': {
            'datagen': {'indicator_count': 100},
            'sites': {
                'localhost': {
                    'taxii': {
                        'poll_interval': 30,
                        'collection': 'system.Default',
                        'ssl': False,
                        'version': 1.1,
                        'user': 'admin',
                        'pass': 'avalanche',
                        'attempt_certificate_validation': False,
                        'path': '/taxii-data',
                        'port': 80},
                    'host': '127.0.0.1',
                    'enabled': True,
                    'stix': {'xmlns_url': 'http://www.your_company.com/', 'xmlns_name': 'yourcompanyname'}
                }
            }
        },
        'daemon': {
            'app_path': '/opt/soltra/edge/repository/adapters/crits',
            'working_dir': '/opt/soltra/edge/repository/adapters/crits',
            'log': {
                'rotate_size': 1024000,
                'rotate_count': 10,
                'file': 'edgy_crits.log'
            },
            'debug': False,
            'pid': 'edgy_crits.pid',
            'mongo': {
                'host': 'localhost',
                'user': None,
                'pass': None,
                'db': 'inbox',
                'port': 27017,
                'collection': 'adapters.crits'
            }
        }
    }

    def test_crits_url(self):
        expected = 'https://127.0.0.1:8080/api/v1/'

        result = crits_url(self.testing_config, 'localhost')

        self.assertEqual(result, expected)

    def test_stix_pkg(self):
        src = 'localhost'
        dest = 'localhost'

        domain_name = 'www.example.com'
        domain = helper.create_domain_name_observable(domain_name)

        url_name = 'http://www.example.com'
        url = helper.create_url_observable(url_name)

        ipv4_name = '127.0.0.1'
        ipv4 = helper.create_ipv4_observable(ipv4_name)
 
        domain_result = stix_pkg(self.testing_config, src, domain, dest=dest)
        domain_value = domain_result.observables.observables[0].object_.properties.value.value

        self.assertEqual(domain_value, domain_name)

        url_result = stix_pkg(self.testing_config, src, url, dest=dest)
        url_value = url_result.observables.observables[0].object_.properties.value.value

        self.assertEqual(url_value, url_name)

        ipv4_result = stix_pkg(self.testing_config, src, ipv4, dest=dest)
        ipv4_value = ipv4_result.observables.observables[0].object_.properties.address_value.value

        self.assertEqual(ipv4_value, ipv4_name)


if __name__ == '__main__':
    unittest.main()

