"""request_token models."""
from __future__ import unicode_literals

import datetime
import logging

from django.conf import settings
from django.contrib.auth import login
from django.contrib.postgres.fields import JSONField
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils.encoding import python_2_unicode_compatible
from django.utils.timezone import now as tz_now

from jwt.exceptions import InvalidAudienceError

from .exceptions import MaxUseError
from .settings import JWT_SESSION_TOKEN_EXPIRY, LOG_TOKEN_ERRORS
from .utils import to_seconds, encode

logger = logging.getLogger(__name__)


class RequestTokenQuerySet(models.query.QuerySet):

    """Custom QuerySet for RquestToken objects."""

    def create_token(self, scope, **kwargs):
        """Create a new RequestToken."""
        return RequestToken(scope=scope, **kwargs).save()


@python_2_unicode_compatible
class RequestToken(models.Model):

    """A link token, targeted for use by a known Django User.

    A RequestToken contains information that can be encoded as a JWT
    (JSON Web Token). It is designed to be used in conjunction with the
    RequestTokenMiddleware (responsible for JWT verification) and the
    @use_request_token decorator (responsible for validating the token
    and setting the request.user correctly).

    Each token must have a 'scope', which is used to tie it to a view function
    that is decorated with the `use_request_token` decorator. The token can
    only be used by functions with matching scopes.

    The token may be set to a specific User, in which case, if the existing
    request is unauthenticated, it will use that user as the `request.user`
    property, allowing access to authenticated views.

    The token may be timebound by the `not_before_time` and `expiration_time`
    properties, which are registered JWT 'claims'.

    The token may be restricted by the number of times it can be used, through
    the `max_use` property, which is incremented each time it's used (NB *not*
    thread-safe).

    The token may also store arbitrary serializable data, which can be used
    by the view function if the request token is valid.

    JWT spec: https://tools.ietf.org/html/rfc7519

    """

    # do not login the user on the request
    LOGIN_MODE_NONE = 'None'
    # login the user, but only for the original request
    LOGIN_MODE_REQUEST = 'Request'
    # login the user fully, but only for single-use short-duration links
    LOGIN_MODE_SESSION = 'Session'

    LOGIN_MODE_CHOICES = (
        (LOGIN_MODE_NONE, 'Do not authenticate'),
        (LOGIN_MODE_REQUEST, 'Authenticate a single request'),
        (LOGIN_MODE_SESSION, 'Authenticate for the entire session'),
    )
    login_mode = models.CharField(
        max_length=10,
        default=LOGIN_MODE_NONE,
        choices=LOGIN_MODE_CHOICES,
        help_text="How should the request be authenticated?"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="request_tokens",
        blank=True, null=True,
        on_delete=models.CASCADE,
        help_text="Intended recipient of the JWT (can be used by anyone if not set)."
    )
    scope = models.CharField(
        max_length=100,
        help_text="Label used to match request to view function in decorator."
    )
    expiration_time = models.DateTimeField(
        blank=True, null=True,
        help_text="Token will expire at this time (raises ExpiredSignatureError)."
    )
    not_before_time = models.DateTimeField(
        blank=True, null=True,
        help_text="Token cannot be used before this time (raises ImmatureSignatureError)."
    )
    data = JSONField(
        help_text="Custom data add to the token, but not encoded (must be fetched from DB).",
        blank=True, null=True,
        default=dict()
    )
    issued_at = models.DateTimeField(
        blank=True, null=True,
        help_text="Time the token was created (set in the initial save)."
    )
    max_uses = models.IntegerField(
        default=1,
        help_text="The maximum number of times the token can be used."
    )
    used_to_date = models.IntegerField(
        default=0,
        help_text="Number of times the token has been used to date (raises MaxUseError)."
    )

    objects = RequestTokenQuerySet.as_manager()

    class Meta:
        verbose_name = "Token"
        verbose_name_plural = "Tokens"

    def __str__(self):
        return "Request token #%s" % (self.id)

    def __repr__(self):
        return '<RequestToken id=%s scope=%s login_mode=\'%s\'>' % (
            self.id, self.scope, self.login_mode)

    @property
    def aud(self):
        """The 'aud' claim, maps to user.id."""
        return self.claims.get('aud')

    @property
    def exp(self):
        """The 'exp' claim, maps to expiration_time."""
        return self.claims.get('exp')

    @property
    def nbf(self):
        """The 'nbf' claim, maps to not_before_time."""
        return self.claims.get('nbf')

    @property
    def iat(self):
        """The 'iat' claim, maps to issued_at."""
        return self.claims.get('iat')

    @property
    def jti(self):
        """The 'jti' claim, maps to id."""
        return self.claims.get('jti')

    @property
    def max(self):
        """The 'max' claim, maps to max_uses."""
        return self.claims.get('max')

    @property
    def sub(self):
        """The 'sub' claim, maps to scope."""
        return self.claims.get('sub')

    @property
    def claims(self):
        """A dict containing all of the DEFAULT_CLAIMS (where values exist)."""
        claims = {
            'max': self.max_uses,
            'sub': self.scope,
            'mod': self.login_mode[:1].lower()
        }
        if self.id is not None:
            claims['jti'] = self.id
        if self.user is not None:
            claims['aud'] = self.user.id
        if self.expiration_time is not None:
            claims['exp'] = to_seconds(self.expiration_time)
        if self.issued_at is not None:
            claims['iat'] = to_seconds(self.issued_at)
        if self.not_before_time is not None:
            claims['nbf'] = to_seconds(self.not_before_time)
        return claims

    def clean(self):
        """Ensure that login_mode setting is valid."""
        if self.login_mode == RequestToken.LOGIN_MODE_NONE:
            pass
        if self.login_mode == RequestToken.LOGIN_MODE_SESSION:
            if self.user is None:
                raise ValidationError(
                    {'user': 'Session token must have a user.'}
                )
            if self.max_uses != 1:
                raise ValidationError(
                    {'max_uses': 'Session token must have max_use of 1.'}
                )
            if self.expiration_time is None:
                raise ValidationError(
                    {'expiration_time': 'Session token must have an expiration_time.'}
                )
        if self.login_mode == RequestToken.LOGIN_MODE_REQUEST:
            if self.user is None:
                raise ValidationError(
                    {'expiration_time': 'Request token must have a user.'}
                )

    def save(self, *args, **kwargs):
        if 'update_fields' not in kwargs:
            self.issued_at = self.issued_at or tz_now()
            if self.login_mode == RequestToken.LOGIN_MODE_SESSION:
                self.expiration_time = self.expiration_time or (
                    self.issued_at +
                    datetime.timedelta(minutes=JWT_SESSION_TOKEN_EXPIRY)
                )
        self.clean()
        super(RequestToken, self).save(*args, **kwargs)
        return self

    def jwt(self):
        """Encode the token claims into a JWT."""
        return encode(self.claims).decode()

    def validate_max_uses(self):
        """Check the token max_uses is still valid.

        Raises MaxUseError if invalid.

        """
        if self.max_uses and self.used_to_date >= self.max_uses:
            raise MaxUseError(
                'RequestToken [%s] has exceeded max uses' % self.id
            )

    def _auth_is_anonymous(self, request):
        """Authenticate anonymous requests."""
        if request.user.is_authenticated:
            raise InvalidAudienceError('Token requires anonymous user.')

        if self.login_mode == RequestToken.LOGIN_MODE_NONE:
            pass

        if self.login_mode == RequestToken.LOGIN_MODE_REQUEST:
            logger.debug(
                'Setting request.user to %r from token %i.',
                self.user, self.id
            )
            request.user = self.user

        if self.login_mode == RequestToken.LOGIN_MODE_SESSION:
            logger.debug(
                'Authenticating request.user as %r from token %i.',
                self.user, self.id
            )
            # I _think_ we can get away with this as we are pulling the
            # user out of the DB, and we are explicitly authenticating
            # the user.
            self.user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, self.user)

        return request

    def _auth_is_authenticated(self, request):
        """Authenticate requests with existing users."""
        if request.user.is_anonymous:
            raise InvalidAudienceError('Token requires authenticated user.')

        if self.login_mode == RequestToken.LOGIN_MODE_NONE:
            return request

        if request.user == self.user:
            return request

        raise InvalidAudienceError(
            "RequestToken [%i] audience mismatch: '%s' != '%s'" %
            (self.id, request.user, self.user)
        )

    def authenticate(self, request):
        """Authenticate an HttpRequest with the token user.

        This method encapsulates the request handling - if the token
        has a user assigned, then this will be added to the request.

        """
        if request.user.is_anonymous:
            return self._auth_is_anonymous(request)
        else:
            return self._auth_is_authenticated(request)

    @transaction.atomic
    def log(self, request, response, error=None):
        """Record the use of a token.

        This is used by the decorator to log each time someone uses the token,
        or tries to. Used for reporting, diagnostics.

        Args:
            request: the HttpRequest object that used the token, from which the
                user, ip and user-agenct are extracted.
            response: the corresponding HttpResponse object, from which the status
                code is extracted.
            error: an InvalidTokenError that gets logged as a RequestTokenError.

        Returns a RequestTokenUse object.

        """
        def rmg(key, default=None):
            return request.META.get(key, default)

        log = RequestTokenLog(
            token=self,
            user=None if request.user.is_anonymous else request.user,
            user_agent=rmg('HTTP_USER_AGENT', 'unknown'),
            client_ip=parse_xff(rmg('HTTP_X_FORWARDED_FOR')) or rmg('REMOTE_ADDR', None),
            status_code=response.status_code
        ).save()
        if error and LOG_TOKEN_ERRORS:
            RequestTokenErrorLog.objects.create_error_log(log, error)
        # NB this will include all error logs - which means that an error log
        # may prohibit further use of the token. Is there a scenario in which
        # this would be the wrong outcome?
        self.used_to_date = self.logs.filter(error__isnull=True).count()
        self.save()
        return log


def parse_xff(header_value):
    """
    Parses out the X-Forwarded-For request header.

    This handles the bug that blows up when multiple IP addresses are
    specified in the header. The docs state that the header contains
    "The originating IP address", but in reality it contains a list
    of all the intermediate addresses. The first item is the original
    client, and then any intermediate proxy IPs. We want the original.

    Returns the first IP in the list, else None.

    """
    try:
        return header_value.split(',')[0].strip()
    except (KeyError, AttributeError):
        return None


@python_2_unicode_compatible
class RequestTokenLog(models.Model):

    """Used to log the use of a RequestToken."""

    token = models.ForeignKey(
        RequestToken,
        related_name='logs',
        help_text="The RequestToken that was used.",
        on_delete=models.CASCADE,
        db_index=True
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True, null=True,
        on_delete=models.CASCADE,
        help_text="The user who made the request (None if anonymous)."
    )
    user_agent = models.TextField(
        blank=True,
        help_text="User-agent of client used to make the request."
    )
    client_ip = models.GenericIPAddressField(
        blank=True,
        null=True,
        unpack_ipv4=True,
        help_text="Client IP of device used to make the request."
    )
    status_code = models.IntegerField(
        blank=True, null=True,
        help_text="Response status code associated with this use of the token."
    )
    timestamp = models.DateTimeField(
        blank=True,
        help_text="Time the request was logged."
    )

    class Meta:
        verbose_name = "Log"
        verbose_name_plural = "Logs"

    def __str__(self):
        if self.user is None:
            return "%s used %s" % (self.token, self.timestamp)
        else:
            return "%s used by %s at %s" % (self.token, self.user, self.timestamp)

    def __repr__(self):
        return '<RequestTokenLog id=%s token=%s timestamp=\'%s\'>' % (
            self.id, self.token.id, self.timestamp)

    def save(self, *args, **kwargs):
        if 'update_fields' not in kwargs:
            self.timestamp = self.timestamp or tz_now()
        super(RequestTokenLog, self).save(*args, **kwargs)
        return self


class RequestTokenErrorLogQuerySet(models.query.QuerySet):

    def create_error_log(self, log, error):
        return RequestTokenErrorLog(
            token=log.token,
            log=log,
            error_type=type(error).__name__,
            error_message=str(error)
        )


@python_2_unicode_compatible
class RequestTokenErrorLog(models.Model):

    """Used to log errors that occur with the use of a RequestToken."""

    token = models.ForeignKey(
        RequestToken,
        related_name='errors',
        on_delete=models.CASCADE,
        help_text="The RequestToken that was used.",
        db_index=True
    )
    log = models.OneToOneField(
        RequestTokenLog,
        related_name='error',
        on_delete=models.CASCADE,
        help_text="The token use against which the error occurred.",
        db_index=True
    )
    error_type = models.CharField(
        max_length=50,
        help_text="The underlying type of error raised."
    )
    error_message = models.CharField(
        max_length=200,
        help_text="The error message supplied."
    )

    objects = RequestTokenErrorLogQuerySet().as_manager()

    class Meta:
        verbose_name = "Error"
        verbose_name_plural = "Errors"

    def __str__(self):
        return self.error_message

    def save(self, *args, **kwargs):
        super(RequestTokenErrorLog, self).save(*args, **kwargs)
        return self
