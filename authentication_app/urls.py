from django.urls import path
from .views import SignupView, activate, LoginView, ResendVerificationEmailView, ForgotPasswordView, PasswordResetConfirmView,home

urlpatterns = [
    path('',home, name='home'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('activate/<int:uid>/<str:token>/', activate, name='activate'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend_verification'),
    path('reset-password/confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'), 
    path('forgotpassword/', ForgotPasswordView.as_view(), name='forgot_password'),
]
