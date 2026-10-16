from django.urls import path

from . import views

urlpatterns = [
    path('', views.home_view, name='home'),
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('profile/', views.profile_view, name='profile'),
    path('mfa/setup/', views.mfa_setup_view, name='mfa_setup'),
    path('mfa/qr/', views.mfa_qr_view, name='mfa_qr'),
    path('mfa/verify/', views.mfa_verify_view, name='mfa_verify'),
    path('mfa/disable/', views.mfa_disable_view, name='mfa_disable'),
    path('password_reset/', views.password_reset_view, name='password_reset'),
    path('reset/<uidb64>/<token>/', views.password_reset_confirm_view, name='password_reset_confirm'),
    path('security-admin/users/', views.admin_users_view, name='admin_users'),
    path(
        'security-admin/users/<int:user_id>/<str:action>/',
        views.admin_user_action_view,
        name='admin_user_action',
    ),
    path('security-admin/events/', views.admin_events_view, name='admin_events'),
]
