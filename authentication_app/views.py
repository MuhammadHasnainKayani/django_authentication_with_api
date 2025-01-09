from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.models import User
from django.urls import reverse
from django.http import HttpResponse
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from .serializers import *
from django.contrib.auth import login
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.utils.http import  urlsafe_base64_encode , urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.urls import reverse
from rest_framework import serializers



def home(request):
    return render(request,'index.html')

class SignupView(generics.CreateAPIView):
    serializer_class = SignupSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        # Initialize the serializer with request data
        serializer = self.get_serializer(data=request.data)
        # Validate the data
        serializer.is_valid(raise_exception=True)
     

        # Generate a token for email verification
        token = default_token_generator.make_token(user)
        # Send the verification email
        self.send_verification_email(user, token,request)
   # Save the data, which calls the create method in the serializer
        user = serializer.save()
        # Save user id in session for later use
        request.session['user_id'] = user.pk

        return Response({"detail": "Verification email sent. Please check your email to activate your account."}, status=status.HTTP_201_CREATED)

    def send_verification_email(self, user, token, request):
        activation_link = reverse('activate', kwargs={'uid': user.pk, 'token': token})
        current_site=get_current_site(request)
        domain=current_site.domain
        activation_url = f"http://{domain}{activation_link}"

        send_mail(
          'Activate your account',
          f'''
          Dear {user.first_name} {user.last_name},

          Thank you for registering. Your account registration was successful.

          Please click the following link to activate your account:
          {activation_url}

          Best regards,
          Muhammad Hasnain
          ''',
          'from@example.com',
          [user.email],
          fail_silently=False,
      )


def activate(request, uid, token):
    user = get_object_or_404(User, pk=uid)

    if default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse("Account activated successfully", status=200)
    else:
        return HttpResponse("Activation link is invalid", status=400)



class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Retrieve the authenticated user from validated data
        user = serializer.validated_data['user']

        # Log the user in
        login(request, user)

        return Response({"detail": "Login successful."}, status=status.HTTP_200_OK)

class ResendVerificationEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        user_id = request.session.get('user_id')
        if not user_id:
            return Response({"detail": "No user found in session."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.get(pk=user_id)

        if user.is_active:
            return Response({"detail": "User is already active."}, status=status.HTTP_400_BAD_REQUEST)

        token = default_token_generator.make_token(user)
        self.send_verification_email(user, token, request)

        return Response({"detail": "Verification email resent. Please check your email to activate your account."}, status=status.HTTP_200_OK)

    def send_verification_email(self, user, token, request):
        activation_link = reverse('activate', kwargs={'uid': user.pk, 'token': token})
        current_site = get_current_site(request)
        domain = current_site.domain
        activation_url = f"http://{domain}{activation_link}"

        send_mail(
                 'Activate your account',
                 f'''
                 Dear {user.first_name} {user.last_name},

                 Thank you for registering. Your account registration was successful.

                 Please click the following link to activate your account:
                 {activation_url}

                 Best regards,
                 Muhammad Hasnain
                 ''',
                 'from@example.com',
                 [user.email],
                 fail_silently=False,
             )



 



class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Extract validated email
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Account not found with this email.")

        # Generate a token for password reset
        token = default_token_generator.make_token(user)

        # Build the password reset URL
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        domain = get_current_site(request).domain
        reset_url = reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token})
        reset_link = f"http://{domain}{reset_url}"

        # Compose and send the email
        send_mail(
            'Password Reset',
            f'Hi {user.first_name},\n\n'
            'You are receiving this email because a password reset request was initiated for your account.\n\n'
            f'Please click the following link to reset your password:\n{reset_link}\n\n'
            'If you did not request a password reset, please ignore this email.\n\n'
            'Thank you.\n',
            'from@example.com', 
            [email],
            fail_silently=False,
        )

        return Response({"detail": "Password reset email sent. Please check your email to reset your password."}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    serializer_class = PasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = urlsafe_base64_decode(uidb64)
            uid = force_str(uid)  # Ensure uid is converted to string if necessary
            user = get_object_or_404(User, pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid reset link.")

        if default_token_generator.check_token(user, token):
            # Update user's password
            new_password = serializer.validated_data['password']
            user.set_password(new_password)
            user.save()

            return Response({"detail": "Password reset successfully."}, status=status.HTTP_200_OK)
        else:
            raise serializers.ValidationError("Invalid reset link.")