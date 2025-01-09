from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from .models import *


class SignupSerializer(serializers.ModelSerializer):
    # Add the 'type' field to allow user to specify if they are 'admin' or 'simple'
    type = serializers.ChoiceField(choices=[ 'simple','admin'], default='simple')

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'type']  
        extra_kwargs = {'password': {'write_only': True}}
    def validate_email(self, value):
        # Check if a user with this email already exists
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("An account with this email already exists. Please login.")
        return value
    def create(self, validated_data):
    # Extract validated data
         email = validated_data['email']
         password = validated_data['password']
         first_name = validated_data.get('first_name', '')
         last_name = validated_data.get('last_name', '')
         user_type = validated_data.get('type', 'user')  # Default to 'user'

         # Create the user and set is_active to False
         user = User.objects.create_user(
             username=email,
             email=email,
             password=password,
             first_name=first_name,
             last_name=last_name
         )
         user.is_active = False  # Set the user as inactive until email verification
         user.save()

    # Create a UserProfile with the user_type
         UserProfile.objects.create(user=user, user_type=user_type)

         return user



class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            # Check if user exists
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise serializers.ValidationError("User with this email does not exist.")

              # Check if user is active
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled.")

            # Authenticate user
            user = authenticate(username=email, password=password)
            if user is None:
                raise serializers.ValidationError("Incorrect password.")

            # Add authenticated user to validated data
            data['user'] = user
            return data
        else:
            raise serializers.ValidationError("Must include both email and password.")





class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Account not found with this email.")

        return value



class PasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)