import unittest


from lib.crits import crits_url

class TestCrits(unittest.TestCase):
    example_config = {
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

        result = crits_url(self.example_config, 'localhost')

        self.assertEqual(result, expected)


if __name__ == '__main__':
    unittest.main()

