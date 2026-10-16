from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    SetPasswordForm,
    UserCreationForm,
)
from django.core.exceptions import ValidationError

User = get_user_model()
GENERIC_LOGIN_ERROR = 'Identifiants invalides ou compte temporairement indisponible.'


class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError('Cette adresse e-mail est déjà utilisée.')
        return email


class SecureAuthenticationForm(AuthenticationForm):
    error_messages = {
        **AuthenticationForm.error_messages,
        'invalid_login': GENERIC_LOGIN_ERROR,
        'inactive': GENERIC_LOGIN_ERROR,
    }

    def confirm_login_allowed(self, user):
        if not user.is_active or user.profile.is_locked():
            raise ValidationError(GENERIC_LOGIN_ERROR, code='invalid_login')


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')

    def clean_username(self):
        username = self.cleaned_data['username'].strip()
        if User.objects.filter(username__iexact=username).exclude(pk=self.instance.pk).exists():
            raise ValidationError('Ce nom d’utilisateur est déjà utilisé.')
        return username

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        if User.objects.filter(email__iexact=email).exclude(pk=self.instance.pk).exists():
            raise ValidationError('Cette adresse e-mail est déjà utilisée.')
        return email


class CurrentPasswordForm(forms.Form):
    password = forms.CharField(
        label='Mot de passe actuel',
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data['password']
        if not self.user.check_password(password):
            raise ValidationError('Mot de passe incorrect.')
        return password


class MfaSetupForm(CurrentPasswordForm):
    code = forms.CharField(
        max_length=6,
        min_length=6,
        label='Code de validation',
        widget=forms.TextInput(attrs={'inputmode': 'numeric', 'autocomplete': 'one-time-code'}),
    )


class MfaVerificationForm(forms.Form):
    code = forms.CharField(
        max_length=64,
        min_length=6,
        label='Code MFA ou code de secours',
        widget=forms.TextInput(attrs={'autocomplete': 'one-time-code'}),
    )


class MfaDisableForm(MfaSetupForm):
    pass


class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(label='Adresse e-mail')


class PasswordResetForm(SetPasswordForm):
    pass


class SecurePasswordChangeForm(PasswordChangeForm):
    pass
