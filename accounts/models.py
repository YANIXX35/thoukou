import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone


def _totp_cipher():
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest())
    return Fernet(key)


class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    otp_secret_encrypted = models.TextField(blank=True, default='')
    otp_enabled = models.BooleanField(default=False)
    last_totp_counter = models.BigIntegerField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    lock_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def otp_secret(self):
        if not self.otp_secret_encrypted:
            return ''
        try:
            return _totp_cipher().decrypt(self.otp_secret_encrypted.encode()).decode()
        except InvalidToken as error:
            raise ValueError('Impossible de déchiffrer le secret TOTP. Vérifiez SECRET_KEY.') from error

    @otp_secret.setter
    def otp_secret(self, value):
        self.otp_secret_encrypted = _totp_cipher().encrypt(value.encode()).decode() if value else ''

    def is_locked(self):
        return self.lock_until is not None and self.lock_until > timezone.now()

    def __str__(self):
        return self.user.username


class BackupCode(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='backup_codes')
    code_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def create_for_user(cls, user, raw_code):
        return cls.objects.create(user=user, code_hash=make_password(raw_code))

    def matches(self, raw_code):
        return check_password(raw_code, self.code_hash)

    def __str__(self):
        return f'Code de secours pour {self.user_id}'


class PasswordResetToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reset_tokens')
    token_digest = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    def is_valid(self):
        return self.used_at is None and self.expires_at > timezone.now() and self.user.is_active

    def __str__(self):
        return f'Jeton de réinitialisation pour {self.user_id}'


class SecurityEvent(models.Model):
    EVENT_LOGIN_SUCCESS = 'login_success'
    EVENT_LOGIN_FAILED = 'login_failed'
    EVENT_LOGOUT = 'logout'
    EVENT_MFA_REQUIRED = 'mfa_required'
    EVENT_MFA_SUCCESS = 'mfa_success'
    EVENT_MFA_FAILED = 'mfa_failed'
    EVENT_PASSWORD_RESET = 'password_reset'
    EVENT_PASSWORD_CHANGED = 'password_changed'
    EVENT_USER_REGISTERED = 'user_registered'
    EVENT_PROFILE_UPDATED = 'profile_updated'
    EVENT_MFA_ENABLED = 'mfa_enabled'
    EVENT_MFA_DISABLED = 'mfa_disabled'
    EVENT_ADMIN_ACTION = 'admin_action'

    EVENT_CHOICES = [
        (EVENT_LOGIN_SUCCESS, 'Connexion réussie'),
        (EVENT_LOGIN_FAILED, 'Connexion échouée'),
        (EVENT_LOGOUT, 'Déconnexion'),
        (EVENT_MFA_REQUIRED, 'MFA requise'),
        (EVENT_MFA_SUCCESS, 'MFA validée'),
        (EVENT_MFA_FAILED, 'MFA refusée'),
        (EVENT_PASSWORD_RESET, 'Mot de passe réinitialisé'),
        (EVENT_PASSWORD_CHANGED, 'Mot de passe modifié'),
        (EVENT_USER_REGISTERED, 'Inscription'),
        (EVENT_PROFILE_UPDATED, 'Profil modifié'),
        (EVENT_MFA_ENABLED, 'MFA activée'),
        (EVENT_MFA_DISABLED, 'MFA désactivée'),
        (EVENT_ADMIN_ACTION, 'Action administrateur'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_events',
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='admin_security_events',
    )
    event_type = models.CharField(max_length=32, choices=EVENT_CHOICES, default=EVENT_LOGIN_FAILED)
    message = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.event_type} - {self.user or "system"}'


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
