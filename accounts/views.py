import hashlib
import ipaddress
import secrets
from datetime import timedelta
from functools import wraps

import pyotp
import qrcode
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.db.models import F, Q
from django.core.mail import send_mail
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.views.decorators.http import require_http_methods, require_POST

from .forms import (
    GENERIC_LOGIN_ERROR,
    MfaDisableForm,
    MfaSetupForm,
    MfaVerificationForm,
    PasswordResetForm,
    PasswordResetRequestForm,
    ProfileForm,
    RegistrationForm,
    SecureAuthenticationForm,
    SecurePasswordChangeForm,
)
from .models import BackupCode, PasswordResetToken, SecurityEvent, UserProfile

User = get_user_model()
LOGIN_IP_WINDOW = timedelta(minutes=15)
LOGIN_IP_LIMIT = 20
RESET_TOKEN_LIFETIME = timedelta(minutes=30)
LOCKOUT_BASE_MINUTES = 5
LOCKOUT_MAX_MINUTES = 24 * 60


def get_client_ip(request):
    remote_addr = request.META.get('REMOTE_ADDR')
    if remote_addr in settings.TRUSTED_PROXY_IPS:
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
        try:
            return str(ipaddress.ip_address(forwarded_for))
        except ValueError:
            return None
    try:
        return str(ipaddress.ip_address(remote_addr)) if remote_addr else None
    except ValueError:
        return None


def log_event(user, event_type, message, request=None, actor=None):
    return SecurityEvent.objects.create(
        user=user,
        actor=actor,
        event_type=event_type,
        message=message,
        ip_address=get_client_ip(request) if request else None,
    )


def ip_is_throttled(ip_address):
    if not ip_address:
        return False
    since = timezone.now() - LOGIN_IP_WINDOW
    return SecurityEvent.objects.filter(
        event_type=SecurityEvent.EVENT_LOGIN_FAILED,
        ip_address=ip_address,
        created_at__gte=since,
    ).count() >= LOGIN_IP_LIMIT


def record_login_failure(user, request):
    if user and user.is_active:
        profile = user.profile
        now = timezone.now()
        UserProfile.objects.filter(pk=profile.pk).filter(
            Q(lock_until__isnull=True) | Q(lock_until__lte=now)
        ).update(failed_login_attempts=F('failed_login_attempts') + 1)
        profile.refresh_from_db()
        if not profile.is_locked() and profile.failed_login_attempts >= 5:
            exponent = min(profile.failed_login_attempts - 5, 16)
            minutes = min(LOCKOUT_BASE_MINUTES * (2 ** exponent), LOCKOUT_MAX_MINUTES)
            profile.lock_until = now + timedelta(minutes=minutes)
            profile.save(update_fields=['lock_until'])
    log_event(user, SecurityEvent.EVENT_LOGIN_FAILED, 'Échec de connexion.', request)


def verify_totp(profile, code):
    secret = profile.otp_secret
    if not secret or not code.isdigit() or len(code) != 6:
        return False
    totp = pyotp.TOTP(secret)
    current_counter = int(timezone.now().timestamp() // totp.interval)
    for counter in range(current_counter - 1, current_counter + 2):
        if counter <= (profile.last_totp_counter or -1):
            continue
        if secrets.compare_digest(totp.at(counter * totp.interval), code):
            consumed = UserProfile.objects.filter(pk=profile.pk).filter(
                Q(last_totp_counter__isnull=True) | Q(last_totp_counter__lt=counter)
            ).update(last_totp_counter=counter)
            if consumed:
                profile.last_totp_counter = counter
                return True
    return False


def consume_backup_code(user, raw_code):
    for backup_code in user.backup_codes.filter(used_at__isnull=True):
        if backup_code.matches(raw_code):
            updated = BackupCode.objects.filter(pk=backup_code.pk, used_at__isnull=True).update(
                used_at=timezone.now()
            )
            if updated:
                return True
    return False


def create_reset_token(user):
    raw_token = secrets.token_urlsafe(32)
    token = PasswordResetToken.objects.create(
        user=user,
        token_digest=hashlib.sha256(raw_token.encode()).hexdigest(),
        expires_at=timezone.now() + RESET_TOKEN_LIFETIME,
    )
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    path = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': raw_token})
    link = f'{settings.PUBLIC_BASE_URL.rstrip("/")}{path}'
    send_mail(
        'Réinitialisation du mot de passe SecureAuth',
        f'Pour choisir un nouveau mot de passe, ouvrez ce lien (valable 30 minutes, à usage unique) :\n{link}',
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )
    return token


def home_view(request):
    return redirect('dashboard' if request.user.is_authenticated else 'login')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    form = RegistrationForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save()
        log_event(user, SecurityEvent.EVENT_USER_REGISTERED, 'Compte créé.', request)
        messages.success(request, 'Votre compte a bien été créé. Vous pouvez vous connecter.')
        return redirect('login')
    return render(request, 'register.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = SecureAuthenticationForm(request, data=request.POST or None)
    if request.method == 'POST':
        ip_address = get_client_ip(request)
        if ip_is_throttled(ip_address):
            form.add_error(None, GENERIC_LOGIN_ERROR)
            log_event(None, SecurityEvent.EVENT_LOGIN_FAILED, 'Tentative bloquée par la limite IP.', request)
            return render(request, 'login.html', {'form': form})

        if form.is_valid():
            user = form.get_user()
            profile = user.profile
            if profile.otp_enabled:
                request.session.cycle_key()
                request.session['mfa_pending_user_id'] = user.pk
                request.session['mfa_failed_attempts'] = 0
                log_event(user, SecurityEvent.EVENT_MFA_REQUIRED, 'Vérification MFA requise.', request)
                return redirect('mfa_verify')
            profile.failed_login_attempts = 0
            profile.lock_until = None
            profile.save(update_fields=['failed_login_attempts', 'lock_until'])
            login(request, user)
            log_event(user, SecurityEvent.EVENT_LOGIN_SUCCESS, 'Connexion réussie.', request)
            next_url = request.GET.get('next', '')
            if url_has_allowed_host_and_scheme(
                next_url,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                return redirect(next_url)
            return redirect('dashboard')

        username = form.data.get('username', '').strip()
        user = User.objects.filter(username__iexact=username).first() if username else None
        if user and user.profile.is_locked():
            log_event(user, SecurityEvent.EVENT_LOGIN_FAILED, 'Échec de connexion.', request)
        elif form.data.get('password'):
            record_login_failure(user, request)
        else:
            log_event(user, SecurityEvent.EVENT_LOGIN_FAILED, 'Échec de connexion.', request)
        form.add_error(None, GENERIC_LOGIN_ERROR)
    return render(request, 'login.html', {'form': form})


@require_POST
def logout_view(request):
    user = request.user if request.user.is_authenticated else None
    logout(request)
    if user:
        log_event(user, SecurityEvent.EVENT_LOGOUT, 'Déconnexion.', request)
    messages.success(request, 'Vous avez été déconnecté.')
    return redirect('login')


@login_required
def dashboard_view(request):
    backup_codes = request.session.pop('new_backup_codes', [])
    audit_events = request.user.security_events.order_by('-created_at')[:8]
    response = render(
        request,
        'dashboard.html',
        {'audit_events': audit_events, 'new_backup_codes': backup_codes},
    )
    response['Cache-Control'] = 'no-store'
    return response


@login_required
def profile_view(request):
    profile_form = ProfileForm(request.POST or None, instance=request.user)
    password_form = SecurePasswordChangeForm(request.user, request.POST or None, prefix='password')
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'profile' and profile_form.is_valid():
            profile_form.save()
            log_event(request.user, SecurityEvent.EVENT_PROFILE_UPDATED, 'Profil modifié.', request)
            messages.success(request, 'Votre profil a été mis à jour.')
            return redirect('profile')
        if action == 'password' and password_form.is_valid():
            password_form.save()
            update_session_auth_hash(request, request.user)
            log_event(request.user, SecurityEvent.EVENT_PASSWORD_CHANGED, 'Mot de passe modifié.', request)
            messages.success(request, 'Votre mot de passe a été modifié.')
            return redirect('profile')
    return render(
        request,
        'profile.html',
        {'profile_form': profile_form, 'password_form': password_form},
    )


@login_required
@require_http_methods(['GET', 'POST'])
def mfa_setup_view(request):
    profile = request.user.profile
    if profile.otp_enabled:
        messages.info(request, 'La MFA est déjà activée.')
        return redirect('mfa_disable')
    if not profile.otp_secret:
        profile.otp_secret = pyotp.random_base32()
        profile.save(update_fields=['otp_secret_encrypted'])
    form = MfaSetupForm(request.user, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        if verify_totp(profile, form.cleaned_data['code']):
            with transaction.atomic():
                profile.otp_enabled = True
                profile.failed_login_attempts = 0
                profile.lock_until = None
                profile.save(update_fields=['otp_enabled', 'failed_login_attempts', 'lock_until'])
                raw_codes = [secrets.token_urlsafe(9) for _ in range(8)]
                BackupCode.objects.filter(user=request.user).delete()
                for raw_code in raw_codes:
                    BackupCode.create_for_user(request.user, raw_code)
            request.session['new_backup_codes'] = raw_codes
            log_event(request.user, SecurityEvent.EVENT_MFA_ENABLED, 'MFA activée.', request)
            messages.success(request, 'MFA activée. Conservez vos codes de secours : ils ne seront affichés qu’une fois.')
            return redirect('dashboard')
        messages.error(request, 'Code TOTP invalide ou déjà utilisé.')
    response = render(
        request,
        'mfa_setup.html',
        {'form': form, 'otp_secret': profile.otp_secret, 'mfa_enabled': False},
    )
    response['Cache-Control'] = 'no-store'
    return response


@login_required
def mfa_qr_view(request):
    profile = request.user.profile
    if not profile.otp_secret:
        return HttpResponseBadRequest('La configuration MFA n’est pas initialisée.')
    totp_url = pyotp.TOTP(profile.otp_secret).provisioning_uri(
        name=request.user.email or request.user.username,
        issuer_name='SecureAuth',
    )
    image = qrcode.make(totp_url)
    from io import BytesIO

    output = BytesIO()
    image.save(output, format='PNG')
    response = HttpResponse(output.getvalue(), content_type='image/png')
    response['Cache-Control'] = 'no-store'
    return response


@login_required
@require_http_methods(['GET', 'POST'])
def mfa_disable_view(request):
    profile = request.user.profile
    if not profile.otp_enabled:
        return redirect('mfa_setup')
    form = MfaDisableForm(request.user, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        if verify_totp(profile, form.cleaned_data['code']):
            with transaction.atomic():
                profile.otp_enabled = False
                profile.otp_secret = ''
                profile.last_totp_counter = None
                profile.save(update_fields=['otp_enabled', 'otp_secret_encrypted', 'last_totp_counter'])
                BackupCode.objects.filter(user=request.user).delete()
            log_event(request.user, SecurityEvent.EVENT_MFA_DISABLED, 'MFA désactivée après réauthentification.', request)
            messages.success(request, 'La MFA a été désactivée.')
            return redirect('dashboard')
        messages.error(request, 'Code TOTP invalide ou déjà utilisé.')
    return render(request, 'mfa_disable.html', {'form': form})


@require_http_methods(['GET', 'POST'])
def mfa_verify_view(request):
    user_id = request.session.get('mfa_pending_user_id')
    user = User.objects.filter(pk=user_id, is_active=True).first() if user_id else None
    if not user or not user.profile.otp_enabled or user.profile.is_locked():
        request.session.pop('mfa_pending_user_id', None)
        request.session.pop('mfa_failed_attempts', None)
        return redirect('login')

    form = MfaVerificationForm(request.POST or None)
    ip_address = get_client_ip(request)
    if request.method == 'POST' and ip_is_throttled(ip_address):
        log_event(user, SecurityEvent.EVENT_LOGIN_FAILED, 'Tentative MFA bloquée par la limite IP.', request)
        log_event(user, SecurityEvent.EVENT_MFA_FAILED, 'Tentative MFA bloquée par la limite IP.', request)
        form.add_error(None, GENERIC_LOGIN_ERROR)
        return render(request, 'mfa_verify.html', {'form': form})

    if request.method == 'POST' and form.is_valid():
        code = form.cleaned_data['code'].strip()
        valid_totp = verify_totp(user.profile, code)
        valid_backup = False if valid_totp else consume_backup_code(user, code)
        if valid_totp or valid_backup:
            user.profile.failed_login_attempts = 0
            user.profile.lock_until = None
            user.profile.save(update_fields=['failed_login_attempts', 'lock_until'])
            request.session.pop('mfa_pending_user_id', None)
            request.session.pop('mfa_failed_attempts', None)
            login(request, user)
            log_event(user, SecurityEvent.EVENT_MFA_SUCCESS, 'Vérification MFA réussie.', request)
            log_event(user, SecurityEvent.EVENT_LOGIN_SUCCESS, 'Connexion réussie après MFA.', request)
            return redirect('dashboard')

        attempts = request.session.get('mfa_failed_attempts', 0) + 1
        request.session['mfa_failed_attempts'] = attempts
        record_login_failure(user, request)
        log_event(user, SecurityEvent.EVENT_MFA_FAILED, 'Code MFA invalide.', request)
        if attempts >= 5 or user.profile.is_locked():
            request.session.pop('mfa_pending_user_id', None)
            request.session.pop('mfa_failed_attempts', None)
        messages.error(request, GENERIC_LOGIN_ERROR)
    return render(request, 'mfa_verify.html', {'form': form})


def password_reset_view(request):
    form = PasswordResetRequestForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email'].strip()
        user = User.objects.filter(email__iexact=email, is_active=True).first()
        if user:
            create_reset_token(user)
        return render(request, 'registration/password_reset_done.html')
    return render(request, 'registration/password_reset_form.html', {'form': form})


def password_reset_confirm_view(request, uidb64, token):
    try:
        from django.utils.http import urlsafe_base64_decode

        user_id = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=user_id, is_active=True)
    except (ValueError, TypeError, User.DoesNotExist, UnicodeDecodeError):
        return render(request, 'registration/password_reset_invalid.html', status=400)

    digest = hashlib.sha256(token.encode()).hexdigest()
    reset_token = PasswordResetToken.objects.filter(user=user, token_digest=digest).first()
    if not reset_token or not reset_token.is_valid():
        return render(request, 'registration/password_reset_invalid.html', status=400)

    form = PasswordResetForm(user, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        with transaction.atomic():
            consumed = PasswordResetToken.objects.filter(
                pk=reset_token.pk,
                used_at__isnull=True,
                expires_at__gt=timezone.now(),
                user__is_active=True,
            ).update(used_at=timezone.now())
            if not consumed:
                return render(request, 'registration/password_reset_invalid.html', status=400)
            form.save()
            PasswordResetToken.objects.filter(user=user, used_at__isnull=True).exclude(
                pk=reset_token.pk
            ).update(used_at=timezone.now())
        log_event(user, SecurityEvent.EVENT_PASSWORD_RESET, 'Mot de passe réinitialisé.', request)
        return render(request, 'registration/password_reset_complete.html')
    response = render(request, 'registration/password_reset_confirm.html', {'form': form})
    response['Cache-Control'] = 'no-store'
    return response


def admin_staff_test(user):
    return user.is_active and user.is_staff


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(request, *args, **kwargs):
        if not admin_staff_test(request.user):
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapped


@admin_required
def admin_users_view(request):
    query = request.GET.get('q', '').strip()
    users = User.objects.order_by('username')
    if query:
        users = users.filter(username__icontains=query) | users.filter(email__icontains=query)
    return render(request, 'admin/users.html', {'users': users[:100], 'query': query})


@require_POST
@admin_required
def admin_user_action_view(request, user_id, action):
    target = get_object_or_404(User, pk=user_id)
    if target.pk == request.user.pk and action in {'deactivate', 'delete'}:
        messages.error(request, 'Vous ne pouvez pas désactiver ou supprimer votre propre compte.')
        return redirect('admin_users')

    if action == 'activate':
        target.is_active = True
        target.save(update_fields=['is_active'])
        message = f'Compte #{target.pk} réactivé.'
    elif action == 'deactivate':
        target.is_active = False
        target.save(update_fields=['is_active'])
        message = f'Compte #{target.pk} désactivé.'
    elif action == 'delete':
        target_id = target.pk
        target.delete()
        message = f'Compte #{target_id} supprimé.'
        log_event(None, SecurityEvent.EVENT_ADMIN_ACTION, message, request, request.user)
        messages.success(request, message)
        return redirect('admin_users')
    elif action == 'reset':
        if not target.email:
            messages.error(request, 'Ce compte ne dispose pas d’adresse e-mail.')
            return redirect('admin_users')
        create_reset_token(target)
        message = f'Lien de réinitialisation envoyé pour le compte #{target.pk}.'
    else:
        return HttpResponseBadRequest('Action inconnue.')

    log_event(target, SecurityEvent.EVENT_ADMIN_ACTION, message, request, request.user)
    messages.success(request, message)
    return redirect('admin_users')


@admin_required
def admin_events_view(request):
    events = SecurityEvent.objects.select_related('user', 'actor')
    event_type = request.GET.get('type', '')
    query = request.GET.get('q', '').strip()
    if event_type in dict(SecurityEvent.EVENT_CHOICES):
        events = events.filter(event_type=event_type)
    if query:
        events = events.filter(user__username__icontains=query)
    return render(
        request,
        'admin/events.html',
        {'events': events[:200], 'event_types': SecurityEvent.EVENT_CHOICES, 'selected_type': event_type, 'query': query},
    )
