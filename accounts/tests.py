import hashlib
import re
from datetime import timedelta
from urllib.parse import urlsplit

import pyotp
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import BackupCode, PasswordResetToken, SecurityEvent
from .views import create_reset_token, get_client_ip

User = get_user_model()
PASSWORD = 'StrongPass123!Secure'


@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class SecureAuthTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='alice',
            email='alice@example.com',
            password=PASSWORD,
        )

    def enable_mfa(self):
        profile = self.user.profile
        profile.refresh_from_db()
        profile.otp_secret = pyotp.random_base32()
        profile.otp_enabled = True
        profile.save(update_fields=['otp_secret_encrypted', 'otp_enabled'])
        return profile

    def test_registration_creates_user(self):
        response = self.client.post(reverse('register'), {
            'username': 'bob',
            'email': 'bob@example.com',
            'password1': PASSWORD,
            'password2': PASSWORD,
        })
        self.assertRedirects(response, reverse('login'))
        self.assertTrue(User.objects.filter(username='bob').exists())

    def test_registration_rejects_invalid_email(self):
        response = self.client.post(reverse('register'), {
            'username': 'bob',
            'email': 'invalid',
            'password1': PASSWORD,
            'password2': PASSWORD,
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username='bob').exists())

    def test_registration_rejects_duplicate_username(self):
        response = self.client.post(reverse('register'), {
            'username': 'alice',
            'email': 'new@example.com',
            'password1': PASSWORD,
            'password2': PASSWORD,
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.filter(username='alice').count(), 1)

    def test_registration_rejects_duplicate_email_case_insensitively(self):
        response = self.client.post(reverse('register'), {
            'username': 'bob',
            'email': 'ALICE@example.com',
            'password1': PASSWORD,
            'password2': PASSWORD,
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username='bob').exists())

    def test_registration_rejects_weak_password(self):
        response = self.client.post(reverse('register'), {
            'username': 'bob',
            'email': 'bob@example.com',
            'password1': '12345678',
            'password2': '12345678',
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username='bob').exists())

    def test_password_is_stored_with_argon2id(self):
        self.assertTrue(self.user.password.startswith('argon2'))
        self.assertNotEqual(self.user.password, PASSWORD)

    def test_login_succeeds(self):
        response = self.client.post(reverse('login'), {'username': 'alice', 'password': PASSWORD})
        self.assertRedirects(response, reverse('dashboard'))
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=self.user,
                event_type=SecurityEvent.EVENT_LOGIN_SUCCESS,
            ).exists()
        )

    def test_login_does_not_redirect_to_external_next_url(self):
        response = self.client.post(
            f'{reverse("login")}?next=https://attacker.example/',
            {'username': 'alice', 'password': PASSWORD},
        )
        self.assertRedirects(response, reverse('dashboard'))

    def test_untrusted_forwarded_ip_is_ignored(self):
        request = self.client.post(
            reverse('login'),
            {'username': 'unknown', 'password': 'WrongPassword'},
            HTTP_X_FORWARDED_FOR='203.0.113.42',
        ).wsgi_request
        self.assertEqual(get_client_ip(request), '127.0.0.1')

    @override_settings(TRUSTED_PROXY_IPS={'10.0.0.1'})
    def test_forwarded_ip_is_used_only_from_trusted_proxy(self):
        request = self.client.post(
            reverse('login'),
            {'username': 'unknown', 'password': 'WrongPassword'},
            REMOTE_ADDR='10.0.0.1',
            HTTP_X_FORWARDED_FOR='203.0.113.42',
        ).wsgi_request
        self.assertEqual(get_client_ip(request), '203.0.113.42')

    def test_bad_password_is_rejected(self):
        response = self.client.post(reverse('login'), {'username': 'alice', 'password': 'WrongPassword'})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_unknown_and_known_username_use_same_login_error(self):
        known = self.client.post(reverse('login'), {'username': 'alice', 'password': 'WrongPassword'})
        unknown = self.client.post(reverse('login'), {'username': 'nobody', 'password': 'WrongPassword'})
        self.assertContains(known, 'Identifiants invalides ou compte temporairement indisponible.')
        self.assertContains(unknown, 'Identifiants invalides ou compte temporairement indisponible.')
        self.assertNotContains(unknown, 'n’existe pas')

    def test_login_session_cookie_is_httponly_and_secure_flag_is_configurable(self):
        self.client.post(reverse('login'), {'username': 'alice', 'password': PASSWORD})
        cookie = self.client.cookies['sessionid']
        self.assertTrue(cookie['httponly'])
        self.assertEqual(cookie['samesite'], 'Lax')
        self.assertTrue(settings.SESSION_EXPIRE_AT_BROWSER_CLOSE)
        self.assertEqual(settings.SESSION_COOKIE_AGE, 1800)

    @override_settings(SESSION_COOKIE_SECURE=True)
    def test_session_cookie_is_secure_when_https_is_enabled(self):
        self.client.post(reverse('login'), {'username': 'alice', 'password': PASSWORD})
        self.assertTrue(self.client.cookies['sessionid']['secure'])
    def test_logout_requires_post(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse('logout'))
        self.assertEqual(response.status_code, 405)

    def test_logout_post_ends_session(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse('logout'))
        self.assertRedirects(response, reverse('login'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse('dashboard'))
        self.assertRedirects(response, f'{reverse("login")}?next={reverse("dashboard")}')

    def test_user_can_only_edit_own_profile(self):
        other = User.objects.create_user(username='other', email='other@example.com', password=PASSWORD)
        self.client.force_login(self.user)
        self.client.post(reverse('profile'), {
            'action': 'profile',
            'username': 'changed',
            'email': 'changed@example.com',
            'first_name': 'Alice',
            'last_name': 'Example',
            'user_id': other.pk,
        })
        other.refresh_from_db()
        self.assertEqual(other.username, 'other')
        self.assertTrue(User.objects.filter(username='changed', pk=self.user.pk).exists())

    def test_profile_output_escapes_user_supplied_html(self):
        self.user.first_name = '<script>alert(1)</script>'
        self.user.save(update_fields=['first_name'])
        self.client.force_login(self.user)
        response = self.client.get(reverse('profile'))
        self.assertNotContains(response, '<script>alert(1)</script>')

    def test_profile_can_be_updated(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse('profile'), {
            'action': 'profile',
            'username': 'alice-new',
            'email': 'alice-new@example.com',
            'first_name': 'Alice',
            'last_name': 'Example',
        })
        self.assertRedirects(response, reverse('profile'))
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, 'alice-new@example.com')

    def test_profile_update_rejects_duplicate_email(self):
        User.objects.create_user(username='other', email='other@example.com', password=PASSWORD)
        self.client.force_login(self.user)
        self.client.post(reverse('profile'), {
            'action': 'profile',
            'username': 'alice',
            'email': 'other@example.com',
            'first_name': '',
            'last_name': '',
        })
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, 'alice@example.com')

    def test_password_change_requires_old_password(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse('profile'), {
            'action': 'password',
            'password-old_password': 'WrongPassword',
            'password-new_password1': 'AnotherStrongPassword123!',
            'password-new_password2': 'AnotherStrongPassword123!',
        })
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(PASSWORD))

    def test_password_change_updates_password_and_preserves_session(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse('profile'), {
            'action': 'password',
            'password-old_password': PASSWORD,
            'password-new_password1': 'AnotherStrongPassword123!',
            'password-new_password2': 'AnotherStrongPassword123!',
        })
        self.assertRedirects(response, reverse('profile'))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('AnotherStrongPassword123!'))
        self.assertIn('_auth_user_id', self.client.session)

    def test_csrf_is_required_for_post(self):
        client = self.client_class(enforce_csrf_checks=True)
        response = client.post(reverse('login'), {'username': 'alice', 'password': PASSWORD})
        self.assertEqual(response.status_code, 403)

    def test_five_failed_logins_cause_temporary_lockout(self):
        for _ in range(5):
            self.client.post(reverse('login'), {'username': 'alice', 'password': 'WrongPassword'})
        self.user.refresh_from_db()
        self.assertTrue(self.user.profile.is_locked())
        self.assertGreaterEqual(self.user.profile.failed_login_attempts, 5)

    def test_lockout_duration_increases(self):
        profile = self.user.profile
        profile.failed_login_attempts = 5
        profile.lock_until = None
        profile.save()
        self.client.post(reverse('login'), {'username': 'alice', 'password': 'WrongPassword'})
        self.user.refresh_from_db()
        self.assertGreater(self.user.profile.lock_until, timezone.now() + timedelta(minutes=9))

    def test_login_attempts_are_limited_per_ip(self):
        for _ in range(20):
            SecurityEvent.objects.create(
                event_type=SecurityEvent.EVENT_LOGIN_FAILED,
                message='Failed test attempt.',
                ip_address='127.0.0.1',
            )
        response = self.client.post(reverse('login'), {'username': 'alice', 'password': PASSWORD})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_mfa_redirects_to_second_factor(self):
        self.enable_mfa()
        response = self.client.post(reverse('login'), {'username': 'alice', 'password': PASSWORD})
        self.assertRedirects(response, reverse('mfa_verify'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_mfa_rejects_invalid_code(self):
        self.enable_mfa()
        self.client.post(reverse('login'), {'username': 'alice', 'password': PASSWORD})
        response = self.client.post(reverse('mfa_verify'), {'code': '000000'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_mfa_attempts_are_limited_per_ip(self):
        self.enable_mfa()
        for _ in range(20):
            SecurityEvent.objects.create(
                event_type=SecurityEvent.EVENT_LOGIN_FAILED,
                message='Failed test attempt.',
                ip_address='127.0.0.1',
            )
        session = self.client.session
        session['mfa_pending_user_id'] = self.user.pk
        session.save()
        response = self.client.post(reverse('mfa_verify'), {'code': '000000'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertContains(response, 'Identifiants invalides ou compte temporairement indisponible.')

    def test_mfa_accepts_totp(self):
        profile = self.enable_mfa()
        self.client.post(reverse('login'), {'username': 'alice', 'password': PASSWORD})
        code = pyotp.TOTP(profile.otp_secret).now()
        response = self.client.post(reverse('mfa_verify'), {'code': code})
        self.assertRedirects(response, reverse('dashboard'))
        self.assertIn('_auth_user_id', self.client.session)
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=self.user,
                event_type=SecurityEvent.EVENT_LOGIN_SUCCESS,
            ).exists()
        )

    def test_totp_code_cannot_be_replayed(self):
        profile = self.enable_mfa()
        code = pyotp.TOTP(profile.otp_secret).now()
        from .views import verify_totp
        self.assertTrue(verify_totp(profile, code))
        self.assertFalse(verify_totp(profile, code))

    def test_totp_secret_is_encrypted_at_rest(self):
        profile = self.enable_mfa()
        raw_secret = profile.otp_secret
        profile.refresh_from_db()
        self.assertNotEqual(profile.otp_secret_encrypted, raw_secret)
        self.assertNotIn(raw_secret, profile.otp_secret_encrypted)

    def test_setup_page_generates_local_qr_code(self):
        self.client.force_login(self.user)
        page = self.client.get(reverse('mfa_setup'))
        qr = self.client.get(reverse('mfa_qr'))
        self.assertEqual(page.status_code, 200)
        self.assertEqual(qr['Content-Type'], 'image/png')
        self.assertEqual(qr['Cache-Control'], 'no-store')

    def test_mfa_activation_generates_hashed_backup_codes(self):
        self.client.force_login(self.user)
        self.client.get(reverse('mfa_setup'))
        profile = self.user.profile
        profile.refresh_from_db()
        code = pyotp.TOTP(profile.otp_secret).now()
        response = self.client.post(reverse('mfa_setup'), {'password': PASSWORD, 'code': code}, follow=True)
        self.assertContains(response, 'Codes de secours')
        backup = self.user.backup_codes.first()
        self.assertIsNotNone(backup)
        self.assertTrue(backup.code_hash.startswith('argon2'))
        self.assertNotIn(backup.code_hash, response.content.decode())

    def test_backup_code_is_consumed_once(self):
        self.enable_mfa()
        backup = BackupCode.create_for_user(self.user, 'backup-secret-once')
        self.client.post(reverse('login'), {'username': 'alice', 'password': PASSWORD})
        first = self.client.post(reverse('mfa_verify'), {'code': 'backup-secret-once'})
        self.assertRedirects(first, reverse('dashboard'))
        self.client.post(reverse('logout'))
        self.client.post(reverse('login'), {'username': 'alice', 'password': PASSWORD})
        second = self.client.post(reverse('mfa_verify'), {'code': 'backup-secret-once'})
        self.assertEqual(second.status_code, 200)
        backup.refresh_from_db()
        self.assertIsNotNone(backup.used_at)

    def test_disabling_mfa_requires_reauthentication(self):
        self.enable_mfa()
        self.client.force_login(self.user)
        response = self.client.post(reverse('mfa_disable'), {'password': 'WrongPassword', 'code': '000000'})
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.profile.otp_enabled)

    def test_disabling_mfa_with_password_and_totp_succeeds(self):
        profile = self.enable_mfa()
        self.client.force_login(self.user)
        code = pyotp.TOTP(profile.otp_secret).now()
        response = self.client.post(
            reverse('mfa_disable'),
            {'password': PASSWORD, 'code': code},
        )
        self.assertRedirects(response, reverse('dashboard'))
        self.user.refresh_from_db()
        self.assertFalse(self.user.profile.otp_enabled)
        self.assertEqual(self.user.profile.otp_secret, '')

    def test_password_reset_request_does_not_reveal_account_existence(self):
        known = self.client.post(reverse('password_reset'), {'email': self.user.email})
        unknown = self.client.post(reverse('password_reset'), {'email': 'unknown@example.com'})
        self.assertEqual(known.content, unknown.content)

    def test_password_reset_token_is_stored_as_digest(self):
        create_reset_token(self.user)
        self.assertEqual(len(mail.outbox), 1)
        raw_token = re.search(r'/reset/[^/]+/([^/\s]+)', mail.outbox[0].body).group(1)
        token = PasswordResetToken.objects.get(user=self.user)
        self.assertEqual(token.token_digest, hashlib.sha256(raw_token.encode()).hexdigest())
        self.assertNotEqual(token.token_digest, raw_token)

    def test_expired_password_reset_token_is_rejected(self):
        create_reset_token(self.user)
        path = urlsplit(re.search(r'https?://\S+', mail.outbox[0].body).group(0)).path
        token = PasswordResetToken.objects.get(user=self.user)
        token.expires_at = timezone.now() - timedelta(seconds=1)
        token.save(update_fields=['expires_at'])
        response = self.client.get(path)
        self.assertEqual(response.status_code, 400)

    def test_password_reset_token_is_single_use(self):
        create_reset_token(self.user)
        path = urlsplit(re.search(r'https?://\S+', mail.outbox[0].body).group(0)).path
        response = self.client.post(path, {
            'new_password1': 'ResetPassword123!Strong',
            'new_password2': 'ResetPassword123!Strong',
        })
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'registration/password_reset_complete.html')
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('ResetPassword123!Strong'))
        self.assertEqual(self.client.get(path).status_code, 400)

    def test_non_admin_cannot_open_admin_console(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse('admin_users'))
        self.assertEqual(response.status_code, 403)

    def test_admin_searches_users(self):
        admin = User.objects.create_user(username='admin', email='admin@example.com', password=PASSWORD, is_staff=True)
        self.client.force_login(admin)
        response = self.client.get(reverse('admin_users'), {'q': 'alice'})
        self.assertContains(response, 'alice')
        self.assertNotContains(response, 'admin@example.com')

    def test_admin_actions_require_post(self):
        admin = User.objects.create_user(username='admin', email='admin@example.com', password=PASSWORD, is_staff=True)
        self.client.force_login(admin)
        response = self.client.get(reverse('admin_user_action', args=[self.user.pk, 'deactivate']))
        self.assertEqual(response.status_code, 405)

    def test_admin_can_deactivate_account(self):
        admin = User.objects.create_user(username='admin', email='admin@example.com', password=PASSWORD, is_staff=True)
        self.client.force_login(admin)
        response = self.client.post(reverse('admin_user_action', args=[self.user.pk, 'deactivate']))
        self.assertRedirects(response, reverse('admin_users'))
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertTrue(SecurityEvent.objects.filter(event_type=SecurityEvent.EVENT_ADMIN_ACTION).exists())

    def test_admin_can_reactivate_account(self):
        self.user.is_active = False
        self.user.save(update_fields=['is_active'])
        admin = User.objects.create_user(username='admin', email='admin@example.com', password=PASSWORD, is_staff=True)
        self.client.force_login(admin)
        response = self.client.post(reverse('admin_user_action', args=[self.user.pk, 'activate']))
        self.assertRedirects(response, reverse('admin_users'))
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)

    def test_admin_can_delete_account_and_audit_action(self):
        admin = User.objects.create_user(username='admin', email='admin@example.com', password=PASSWORD, is_staff=True)
        target_id = self.user.pk
        self.client.force_login(admin)
        response = self.client.post(reverse('admin_user_action', args=[target_id, 'delete']))
        self.assertRedirects(response, reverse('admin_users'))
        self.assertFalse(User.objects.filter(pk=target_id).exists())
        self.assertTrue(
            SecurityEvent.objects.filter(
                actor=admin,
                event_type=SecurityEvent.EVENT_ADMIN_ACTION,
                message=f'Compte #{target_id} supprimé.',
            ).exists()
        )

    def test_admin_can_force_password_reset_with_local_email(self):
        admin = User.objects.create_user(username='admin', email='admin@example.com', password=PASSWORD, is_staff=True)
        self.client.force_login(admin)
        response = self.client.post(reverse('admin_user_action', args=[self.user.pk, 'reset']))
        self.assertRedirects(response, reverse('admin_users'))
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(PasswordResetToken.objects.filter(user=self.user).exists())

    def test_admin_cannot_deactivate_self(self):
        admin = User.objects.create_user(username='admin', email='admin@example.com', password=PASSWORD, is_staff=True)
        self.client.force_login(admin)
        self.client.post(reverse('admin_user_action', args=[admin.pk, 'deactivate']))
        admin.refresh_from_db()
        self.assertTrue(admin.is_active)

    def test_audit_event_records_ip_without_password(self):
        self.client.post(reverse('login'), {'username': 'alice', 'password': 'NeverLogThisSecret'})
        event = SecurityEvent.objects.filter(event_type=SecurityEvent.EVENT_LOGIN_FAILED).latest('created_at')
        self.assertEqual(event.ip_address, '127.0.0.1')
        self.assertNotIn('NeverLogThisSecret', event.message)

    def test_security_headers_are_present(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response['X-Frame-Options'], 'DENY')
        self.assertIn("default-src 'self'", response['Content-Security-Policy'])

    def test_referrer_policy_keeps_same_origin_for_csrf(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response['Referrer-Policy'], 'same-origin')

    def test_browser_login_with_origin_header_passes_csrf(self):
        # Reproduit un vrai navigateur : jeton CSRF + en-tête Origin du site
        client = self.client_class(enforce_csrf_checks=True)
        client.get(reverse('login'))
        token = client.cookies['csrftoken'].value
        response = client.post(
            reverse('login'),
            {'username': 'alice', 'password': PASSWORD, 'csrfmiddlewaretoken': token},
            HTTP_ORIGIN='http://testserver',
        )
        self.assertRedirects(response, reverse('dashboard'))

    def test_post_with_null_origin_is_rejected(self):
        client = self.client_class(enforce_csrf_checks=True)
        client.get(reverse('login'))
        token = client.cookies['csrftoken'].value
        response = client.post(
            reverse('login'),
            {'username': 'alice', 'password': PASSWORD, 'csrfmiddlewaretoken': token},
            HTTP_ORIGIN='null',
        )
        self.assertEqual(response.status_code, 403)

    def test_html_pages_are_not_cached(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response['Cache-Control'], 'no-store')
