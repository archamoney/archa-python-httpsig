#!/usr/bin/env python
import sys
import os

import unittest
from datetime import datetime, timezone

import pytest

import httpsig.sign as sign
from httpsig.sign_algorithms import PSS
from httpsig.utils import parse_authorization_header, HttpSigException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

sign.DEFAULT_ALGORITHM = "hs2019"


class TestSign(unittest.TestCase):
    test_method = 'POST'
    test_path = '/foo?param=value&pet=dog'
    header_host = 'example.com'
    header_date = 'Thu, 05 Jan 2014 21:31:40 GMT'
    header_content_type = 'application/json'
    header_digest = 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE='
    header_content_length = '18'

    def setUp(self):
        self.key_path_2048 = os.path.join(
            os.path.dirname(__file__), 'rsa_private_2048.pem')
        with open(self.key_path_2048, 'rb') as f:
            self.key_2048 = f.read()

        self.key_path_1024 = os.path.join(
            os.path.dirname(__file__), 'rsa_private_1024.pem')
        with open(self.key_path_1024, 'rb') as f:
            self.key_1024 = f.read()

    def test_default(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS(hash_algorithm="sha512", salt_length=0))
        unsigned = {
            'Date': self.header_date
        }
        signed = hs.sign(unsigned, created=self.header_date)
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'hs2019')
        self.assertEqual(params['signature'], 'OIBXItZkVQwd0uimd0TNJqyOtlXNKBPLe553wCbaGbYIQwuvybb6zqERRa1lWUy2055ABXrEdIkkyNSo/mem+74PsejRi55iByPkeiUzVN4oRNe78Gih08k6xRUReVEwuqj5QgmsZ2KlIBUHXvHXtwZFVJTwMntYlpG/YyITbP5qGcubPlQjB5ppCwI9w4+RZhWTrhkgI74K7k3COmqotY2XxofaMhqbEGEyAFw4fcvAODLlLZhHrXR23cBeAH837BBeepL3kXqLo47CFpWttA8VGDfFPrc3jemtwkONQhRtHR3UhJJyT2Vx0+NGdFPUR/MOm+aSkZFAz9w6LmfiOA==')  # noqa: E501

    def test_other_default(self):

        hs = sign.HeaderSigner(key_id='Test', secret=self.key_1024, sign_algorithm=PSS(hash_algorithm="sha512", salt_length=0))
        unsigned = {
            'Date': self.header_date
        }
        signed = hs.sign(unsigned, created=self.header_date)
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'hs2019')
        self.assertEqual(params['signature'],
                         'jZb/d7fRF3ClpVYGK0737T9erwFwVtvyADouOPuk00X7me2q4DKroGxMYWYOJpn53rCgGq/XtY+j8I/ImezFCVYiNox0cqiMVS9Lt7cH21XXrmRfwlSPVYzjaXd8NLu4SBKAtB7nNQLsZDt3fH+pidK9tm6Ak3pcg6o0eUuUZNA=')

    def test_basic(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS(salt_length=0), headers=[
            '(request-target)',
            'host',
            '(created)',
        ])
        unsigned = {
            'Host': self.header_host,
            'Date': self.header_date,
        }
        signed = hs.sign(
            unsigned, method=self.test_method, path=self.test_path, created=self.header_date)

        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'hs2019')
        self.assertEqual(
            params['headers'], '(request-target) host (created)')
        self.assertEqual(params['signature'], 'ItkDA2bm25g1FfaOsk81ddN/5YxIDovWxdNS1WuD6RztHk+jfRpnaqC7HyX932dFNdNEw8xYeCvy5Mc1We9491shw4VJA1e0+WBKXCT0TWoTsJ6Ti34Q07QLmAi4bBOtbkNo98yaGTSvSTluElbyEo+oPb1PH3Ab62wl340gjBync7xnTWnGivjRbQ+l+YyIREvzFoNnB+UruV3tDXgMs8YqyP6p5Of+XXOZKuJNk4Roi+3dX19vUSNrDUKPeadMSfZDVhwOiDx+cjlU894IhEkxpcOK5shhgZRqAwv4lZrG4O65WYUE7bxEbIaOpfvB+kE1xd+LGGNj2P2GALcmHg==')  # noqa: E501

    def test_all(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS("sha512", salt_length=0),  headers=[
            '(request-target)',
            'host',
            '(created)',
            'content-type',
            'digest',
            'content-length'
        ])
        unsigned = {
            'Host': self.header_host,
            'Date': self.header_date,
            'Content-Type': self.header_content_type,
            'Digest': self.header_digest,
            'Content-Length': self.header_content_length,
        }
        signed = hs.sign(
            unsigned, method=self.test_method, path=self.test_path, created=self.header_date)

        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'hs2019')
        self.assertEqual(
            params['headers'],
            '(request-target) host (created) content-type digest content-length')
        self.assertEqual(params['signature'], 'XLe15wakQd34/GXzWmFczhuwVelF/ZYiKv+VvIE+C/5M11Ls/zAsv3FE+oDjkX49h8q2fGUXcdVxheokJHD0MKiEFSLCDpH4jU9x+7sX7MMxDQ5Dgk2zDda5Y8LSDlteh6coBKspx11KJrU8oiB9BFoIPLiI7loBeea5F6Wfcp4taxOHo7Q6h/xsVvKzTeUW8Z/pYSECxq7YYkmcugP+jXyF72sroq/Fc/GVVWQTIyG8y3NqsW7FeSBfK3Zf+6inii+kAyUaxaa5ol5nmqUxSYCXUg/X4L+XSA3D7rfDag44I+qkIGPnL7wbzECSEeY2A2l2l4eXGSyqNchpdrgdIQ==')  # noqa: E501

    def test_default_deprecated_256(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_1024, algorithm="rsa-sha256")
        unsigned = {
            'Date': self.header_date
        }
        signed = hs.sign(unsigned, created=self.header_date)
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['signature'], 'Fj7aYyirHvtcQcXrH5z+YYCHU4dA8j3SMimwM+3UHm3teNZD/Y+VmwtGf0lrMLTcM5qN10xt0PdsQ86QpRTwAO4XEIl8Pzn1JOmnFz/RH126M3A6GVftVhDpCE2v4OSCW/lcHPAh0WFG5ZLG9NmeRWEwJSpv0EoYv4SiTvPycyE=')  # noqa: E501

    def test_unsupported_hash_algorithm(self):
        with pytest.raises(HttpSigException) as e:
            sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS("sha123", salt_length=0))
        self.assertEqual(str(e.value), "Unsupported hash algorithm")

    def test_deprecated_hash_algorithm(self):
        with pytest.raises(HttpSigException) as e:
            sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS("sha256", salt_length=0))
        self.assertEqual(str(e.value), "Hash algorithm: sha256 is deprecated. Please use: sha512")

    def test_empty_secret(self):
        with self.assertRaises(ValueError) as e:
            sign.HeaderSigner(key_id='Test', secret='', headers=[
                '(request-target)',
                'host',
                'date',
                'content-type',
                'digest',
                'content-length'
            ])
        self.assertEqual(str(e.exception), "secret can't be empty")

    def test_none_secret(self):
        with self.assertRaises(ValueError) as e:
            sign.HeaderSigner(key_id='Test', secret=None, headers=[
                '(request-target)',
                'host',
                'date',
                'content-type',
                'digest',
                'content-length'
            ])
        self.assertEqual(str(e.exception), "secret can't be empty")

    def test_huge_secret(self):
        with self.assertRaises(ValueError) as e:
            sign.HeaderSigner(key_id='Test', secret='x' * 1000000, headers=[
                '(request-target)',
                'host',
                'date',
                'content-type',
                'digest',
                'content-length'
            ])
        self.assertEqual(str(e.exception), "secret cant be larger than 100000 chars")

    def test_empty_key_id(self):
        with self.assertRaises(ValueError) as e:
            sign.HeaderSigner(key_id='', secret=self.key_2048, headers=[
                '(request-target)',
                'host',
                'date',
                'content-type',
                'digest',
                'content-length'
            ])
        self.assertEqual(str(e.exception), "key_id can't be empty")

    def test_none_key_id(self):
        with self.assertRaises(ValueError) as e:
            sign.HeaderSigner(key_id=None, secret=self.key_2048, headers=[
                '(request-target)',
                'host',
                'date',
                'content-type',
                'digest',
                'content-length'
            ])
        self.assertEqual(str(e.exception), "key_id can't be empty")

    def test_huge_key_id(self):
        with self.assertRaises(ValueError) as e:
            sign.HeaderSigner(key_id='x' * 1000000, secret=self.key_2048, headers=[
                '(request-target)',
                'host',
                'date',
                'content-type',
                'digest',
                'content-length'
            ])
        self.assertEqual(str(e.exception), "key_id cant be larger than 100000 chars")

    def test_empty_method(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS("sha512", salt_length=0), headers=[
            '(request-target)',
            'host',
            'date',
            'content-type',
            'digest',
            'content-length'
        ])
        unsigned = {
            'Host': self.header_host,
            'Date': self.header_date,
            'Content-Type': self.header_content_type,
            'Digest': self.header_digest,
            'Content-Length': self.header_content_length,
        }

        with self.assertRaises(ValueError) as e:
            hs.sign(unsigned, method='', path=self.test_path)
        self.assertEqual(str(e.exception), 'method and path arguments required when using "(request-target)"')

    def test_none_method(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS("sha512", salt_length=0), headers=[
            '(request-target)',
            'host',
            'date',
            'content-type',
            'digest',
            'content-length'
        ])
        unsigned = {
            'Host': self.header_host,
            'Date': self.header_date,
            'Content-Type': self.header_content_type,
            'Digest': self.header_digest,
            'Content-Length': self.header_content_length,
        }

        with self.assertRaises(ValueError) as e:
            hs.sign(unsigned, method=None, path=self.test_path)
        self.assertEqual(str(e.exception), 'method and path arguments required when using "(request-target)"')

    def test_empty_path(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS("sha512", salt_length=0), headers=[
            '(request-target)',
            'host',
            'date',
            'content-type',
            'digest',
            'content-length'
        ])
        unsigned = {
            'Host': self.header_host,
            'Date': self.header_date,
            'Content-Type': self.header_content_type,
            'Digest': self.header_digest,
            'Content-Length': self.header_content_length,
        }

        with self.assertRaises(ValueError) as e:
            hs.sign(unsigned, method=self.test_method, path='')
        self.assertEqual(str(e.exception), 'method and path arguments required when using "(request-target)"')

    def test_none_path(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS("sha512", salt_length=0), headers=[
            '(request-target)',
            'host',
            'date',
            'content-type',
            'digest',
            'content-length'
        ])
        unsigned = {
            'Host': self.header_host,
            'Date': self.header_date,
            'Content-Type': self.header_content_type,
            'Digest': self.header_digest,
            'Content-Length': self.header_content_length,
        }

        with self.assertRaises(ValueError) as e:
            hs.sign(unsigned, method=self.test_method, path=None)
        self.assertEqual(str(e.exception), 'method and path arguments required when using "(request-target)"')

    def test_missing_header_host(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS("sha512", salt_length=0), headers=[
            '(request-target)',
            'host',
            'date',
            'content-type',
            'digest',
            'content-length'
        ])
        unsigned = {
            'Date': self.header_date,
            'Content-Type': self.header_content_type,
            'Digest': self.header_digest,
            'Content-Length': self.header_content_length,
        }

        with self.assertRaises(ValueError) as e:
            hs.sign(unsigned, method=self.test_method, path=self.test_path)
        self.assertEqual(str(e.exception), 'missing required header "host"')

    def test_missing_header_date(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS("sha512", salt_length=0), headers=[
            '(request-target)',
            'host',
            'date',
            'content-type',
            'digest',
            'content-length'
        ])
        unsigned = {
            'Host': self.header_host,
            'Content-Type': self.header_content_type,
            'Digest': self.header_digest,
            'Content-Length': self.header_content_length,
        }

        with self.assertRaises(ValueError) as e:
            hs.sign(unsigned, method=self.test_method, path=self.test_path)
        self.assertEqual(str(e.exception), 'missing required header "date"')

    def test_missing_header_digest(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key_2048, sign_algorithm=PSS("sha512", salt_length=0), headers=[
            '(request-target)',
            'host',
            'date',
            'content-type',
            'digest',
            'content-length'
        ])
        unsigned = {
            'Host': self.header_host,
            'Date': self.header_date,
            'Content-Type': self.header_content_type,
            'Content-Length': self.header_content_length,
        }

        with self.assertRaises(ValueError) as e:
            hs.sign(unsigned, method=self.test_method, path=self.test_path)
        self.assertEqual(str(e.exception), 'missing required header "digest"')
