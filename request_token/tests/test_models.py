# -*- coding: utf-8 -*-
"""request_token model tests."""
import datetime
import mock
import six

from jwt.exceptions import InvalidAudienceError

from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.http import HttpResponse
from django.test import TestCase, RequestFactory
from django.utils.timezone import now as tz_now

from ..models import RequestToken, RequestTokenLog, parse_xff
from ..exceptions import MaxUseError
from ..settings import JWT_SESSION_TOKEN_EXPIRY
from ..utils import to_seconds, decode


class RequestTokenTests(TestCase):

    """RequestToken model property and method tests."""

    def setUp(self):
        # ensure user has unicode chars
        self.user = get_user_model().objects.create_user(
            'zoidberg',
            first_name=u'ß∂ƒ©˙∆',
            last_name=u'ƒ∆'
        )

    def test_defaults(self):
        token = RequestToken()
        self.assertIsNone(token.user)
        self.assertEqual(token.scope, '')
        self.assertEqual(token.login_mode, RequestToken.LOGIN_MODE_NONE)
        self.assertIsNone(token.expiration_time)
        self.assertIsNone(token.not_before_time)
        self.assertEqual(token.data, "{}")
        self.assertIsNone(token.issued_at)
        self.assertEqual(token.max_uses, 1)
        self.assertEqual(token.used_to_date, 0)

    def test_string_repr(self):
        token = RequestToken(user=self.user)
        self.assertIsNotNone(str(token))
        self.assertIsNotNone(repr(token))
        if six.PY2:
            self.assertIsNotNone(unicode(token))

    def test_save(self):
        token = RequestToken().save()
        self.assertIsNotNone(token)
        self.assertIsNone(token.user)
        self.assertEqual(token.scope, '')
        self.assertEqual(token.login_mode, RequestToken.LOGIN_MODE_NONE)
        self.assertIsNone(token.expiration_time)
        self.assertIsNone(token.not_before_time)
        self.assertEqual(token.data, "{}")
        self.assertIsNotNone(token.issued_at)
        self.assertEqual(token.max_uses, 1)
        self.assertEqual(token.used_to_date, 0)

        token.issued_at = None
        token = token.save(update_fields=['issued_at'])
        self.assertIsNone(token.issued_at)

        now = datetime.datetime.utcnow()
        expires = now + datetime.timedelta(minutes=JWT_SESSION_TOKEN_EXPIRY)
        with mock.patch('request_token.models.tz_now', lambda: now):
            token = RequestToken(
                login_mode=RequestToken.LOGIN_MODE_SESSION,
                user=self.user,
                scope="foo"
            )
            self.assertIsNone(token.issued_at)
            self.assertIsNone(token.expiration_time)
            token.save()
            self.assertEqual(token.issued_at, now)
            self.assertEqual(token.expiration_time, expires)

    def test_claims(self):
        token = RequestToken()
        # raises error with no id set - put into context manager as it's
        # an attr, not a callable
        self.assertEqual(len(token.claims), 3)
        self.assertEqual(token.max, 1)
        self.assertEqual(token.sub, '')
        self.assertIsNone(token.jti)
        self.assertIsNone(token.aud)
        self.assertIsNone(token.exp)
        self.assertIsNone(token.nbf)
        self.assertIsNone(token.iat)

        # now let's set some properties
        token.user = self.user
        self.assertEqual(token.aud, self.user.id)
        self.assertEqual(len(token.claims), 4)

        token.login_mode = RequestToken.LOGIN_MODE_REQUEST
        self.assertEqual(token.claims['mod'], RequestToken.LOGIN_MODE_REQUEST[:1].lower())
        self.assertEqual(len(token.claims), 4)

        now = datetime.datetime.utcnow()
        now_sec = to_seconds(now)

        token.expiration_time = now
        self.assertEqual(token.exp, now_sec)
        self.assertEqual(len(token.claims), 5)

        token.not_before_time = now
        self.assertEqual(token.nbf, now_sec)
        self.assertEqual(len(token.claims), 6)

        # saving updates the id and issued_at timestamp
        with mock.patch('request_token.models.tz_now', lambda: now):
            token.save()
            self.assertEqual(token.iat, now_sec)
            self.assertEqual(token.jti, token.id)
            self.assertEqual(len(token.claims), 8)

    def test_json(self):
        """Test the json method."""
        token = RequestToken(data='{"foo": true}')
        self.assertEqual(token.json, {"foo": True})
        token.data = 'foo'
        with self.assertRaises(ValueError):
            token.json

        def assertData(value, expected):
            token.json = value
            self.assertEqual(token.data, expected)

        assertData({'foo': True}, '{"foo": true}')
        assertData({'foo': None}, '{"foo": null}')
        assertData("foo", '"foo"')
        assertData(1, '1')

    def test_clean(self):
        token = RequestToken(
            login_mode=RequestToken.LOGIN_MODE_NONE,
            # user=self.user
        )
        token.clean()
        # set a user, should now fail validation
        token.user = self.user
        self.assertRaises(ValidationError, token.clean)

        # request mode
        token.login_mode = RequestToken.LOGIN_MODE_REQUEST
        token.clean()
        token.user = None
        self.assertRaises(ValidationError, token.clean)

        def reset_session():
            """Reset properties so that token passes validation."""
            token.login_mode = RequestToken.LOGIN_MODE_SESSION
            token.user = self.user
            token.issued_at = datetime.datetime.utcnow()
            token.expiration_time = token.issued_at + datetime.timedelta(minutes=1)
            token.max_uses = 1

        def assertValidationFails(field_name):
            with self.assertRaises(ValidationError) as ctx:
                token.clean()
            self.assertTrue(field_name in dict(ctx.exception))

        # check the rest_session works!
        reset_session()
        token.clean()
        token.max_uses = 10
        assertValidationFails('max_uses')

        reset_session()
        token.user = None
        assertValidationFails('user')

        reset_session()
        token.expiration_time = None
        assertValidationFails('expiration_time')

    def test_log(self):
        token = RequestToken().save()
        factory = RequestFactory()
        request = factory.get('/')
        request.user = AnonymousUser()
        request.META = {}
        response = HttpResponse("foo", status=123)

        def assertUsedToDate(expected):
            token.refresh_from_db(fields=['used_to_date'])
            self.assertEqual(token.used_to_date, expected)

        log = token.log(request, response)
        self.assertEqual(RequestTokenLog.objects.get(), log)
        self.assertEqual(log.user, None)
        self.assertEqual(log.token, token)
        self.assertEqual(log.user_agent, 'unknown')
        self.assertEqual(log.client_ip, 'unknown')
        self.assertEqual(log.status_code, 123)
        assertUsedToDate(1)

        request.META['REMOTE_ADDR'] = '192.168.0.1'
        log = token.log(request, response)
        self.assertEqual(log.client_ip, '192.168.0.1')
        assertUsedToDate(2)

        request.META['HTTP_X_FORWARDED_FOR'] = '192.168.0.2'
        log = token.log(request, response)
        self.assertEqual(log.client_ip, '192.168.0.2')
        assertUsedToDate(3)

        request.META['HTTP_USER_AGENT'] = 'test_agent'
        log = token.log(request, response)
        self.assertEqual(log.user_agent, 'test_agent')
        token.refresh_from_db(fields=['used_to_date'])
        assertUsedToDate(4)

    def test_jwt(self):
        token = RequestToken(id=1, scope='foo').save()
        jwt = token.jwt()
        self.assertEqual(decode(jwt), token.claims)

    def test_validate_max_uses(self):
        token = RequestToken(max_uses=1, used_to_date=0)
        token.validate_max_uses()
        token.used_to_date = token.max_uses
        self.assertRaises(MaxUseError, token.validate_max_uses)

    def test__auth_is_anonymous(self):
        factory = RequestFactory()
        middleware = SessionMiddleware()
        anon = AnonymousUser()
        request = factory.get('/foo')
        middleware.process_request(request)
        request.user = anon

        # try default token
        token = RequestToken.objects.create_token(
            scope="foo",
            max_uses=10,
            login_mode=RequestToken.LOGIN_MODE_NONE
        )
        request = token._auth_is_anonymous(request)
        self.assertEqual(request.user, anon)

        # try request token
        user1 = get_user_model().objects.create_user(username="Finbar")
        token = RequestToken.objects.create_token(
            user=user1,
            scope="foo",
            max_uses=10,
            login_mode=RequestToken.LOGIN_MODE_REQUEST
        )
        token._auth_is_anonymous(request)
        self.assertEqual(request.user, user1)
        self.assertFalse(hasattr(token.user, 'backend'))

        # try a session token
        logout(request)
        request.user = anon
        token.login_mode = RequestToken.LOGIN_MODE_SESSION
        request = token._auth_is_anonymous(request)
        self.assertEqual(request.user, user1)
        self.assertEqual(token.user.backend, 'django.contrib.auth.backends.ModelBackend')

    def test__auth_is_authenticated(self):
        factory = RequestFactory()
        middleware = SessionMiddleware()
        request = factory.get('/foo')
        middleware.process_request(request)
        user1 = get_user_model().objects.create_user(username="Jekyll")
        request.user = user1

        # try default token
        token = RequestToken.objects.create_token(
            scope="foo",
            max_uses=10,
            login_mode=RequestToken.LOGIN_MODE_NONE
        )
        request = token._auth_is_authenticated(request)
        self.assertEqual(request.user, user1)

        # try request token
        token = RequestToken.objects.create_token(
            user=user1,
            scope="foo",
            max_uses=10,
            login_mode=RequestToken.LOGIN_MODE_REQUEST
        )
        request = token._auth_is_authenticated(request)

        token.login_mode = RequestToken.LOGIN_MODE_SESSION
        request = token._auth_is_authenticated(request)
        self.assertEqual(request.user, user1)

        token.user = get_user_model().objects.create_user(username="Hyde")
        self.assertRaises(InvalidAudienceError, token._auth_is_authenticated, request)

    def test_authenticate(self):
        factory = RequestFactory()
        middleware = SessionMiddleware()
        anon = AnonymousUser()
        request = factory.get('/foo')
        middleware.process_request(request)
        request.user = anon

        user1 = get_user_model().objects.create_user(username="Finbar")
        token = RequestToken.objects.create_token(
            user=user1,
            scope="foo",
            max_uses=10,
            login_mode=RequestToken.LOGIN_MODE_REQUEST
        )
        token.authenticate(request)
        self.assertEqual(request.user, user1)

        request.user = get_user_model().objects.create_user(username="Hyde")
        self.assertRaises(InvalidAudienceError, token.authenticate, request)

    def test_parse_xff(self):

        def assertMeta(meta, expected):
            self.assertEqual(parse_xff(meta), expected)

        assertMeta(None, None)
        assertMeta('', '')
        assertMeta('foo', 'foo')
        assertMeta('foo, bar, baz', 'foo')
        assertMeta('foo , bar, baz', 'foo')
        assertMeta("8.8.8.8, 123.124.125.126", '8.8.8.8')


class RequestTokenQuerySetTests(TestCase):

    """RequestTokenQuerySet class tests."""

    def test_create_token(self):
        self.assertRaises(TypeError, RequestToken.objects.create_token)
        RequestToken.objects.create_token(scope="foo")
        self.assertEqual(RequestToken.objects.get().scope, 'foo')


class RequestTokenLogTests(TestCase):

    """RequestTokenLog model property and method tests."""

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            'zoidberg',
            first_name=u'∂ƒ©˙∆',
            last_name=u'†¥¨^'
        )
        self.token = RequestToken.objects.create_token(
            scope='foo',
            user=self.user,
            login_mode=RequestToken.LOGIN_MODE_REQUEST
        )

    def test_defaults(self):
        log = RequestTokenLog(
            token=self.token,
            user=self.user
        )
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.token, self.token)
        self.assertEqual(log.user_agent, '')
        self.assertEqual(log.client_ip, None)
        self.assertIsNone(log.timestamp)

        token = RequestToken(user=self.user)
        self.assertIsNotNone(str(token))
        self.assertIsNotNone(repr(token))
        if six.PY2:
            self.assertIsNotNone(unicode(token))

    def test_string_repr(self):
        log = RequestTokenLog(
            token=self.token,
            user=self.user
        )
        self.assertIsNotNone(str(log))
        self.assertIsNotNone(repr(log))
        if six.PY2:
            self.assertIsNotNone(unicode(log))

        log.user = None
        self.assertIsNotNone(str(log))
        self.assertIsNotNone(repr(log))
        if six.PY2:
            self.assertIsNotNone(unicode(log))

    def test_save(self):
        log = RequestTokenLog(
            token=self.token,
            user=self.user
        ).save()
        self.assertIsNotNone(log.timestamp)

        log.timestamp = None
        self.assertRaises(IntegrityError, log.save, update_fields=['timestamp'])

    def test_ipv6(self):
        """Test that IP v4 and v6 are handled."""
        log = RequestTokenLog(
            token=self.token,
            user=self.user
        ).save()
        self.assertIsNone(log.client_ip)

        def assertIP(ip):
            log.client_ip = ip
            log.save()
            self.assertEqual(log.client_ip, ip)

        assertIP('192.168.0.1')
        # taken from http://ipv6.com/articles/general/IPv6-Addressing.htm
        assertIP('2001:cdba:0000:0000:0000:0000:3257:9652')
        assertIP('2001:cdba:0:0:0:0:3257:9652')
        assertIP('2001:cdba::3257:9652')
