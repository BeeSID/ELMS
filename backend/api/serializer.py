from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from userauths.models import Profile, User

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['full_name'] = user.full_name
        token['email'] = user.email
        token['username'] = user.username
        return token

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['full_name', 'email', 'password', 'password2']
def validate(self, attr):
    if attr['password'] != attr['password2']:
        raise serializers.ValidationError({"password": "password fields didn't match"})
        
    return attr
def create(self, validated_data):
    password = validated_data.pop('password')
    password2 = validated_data.pop('password2')
    if password != password2:
        raise serializers.ValidationError({'password': 'Passwords must match.'})
    user = User.objects.create_user(**validated_data)
    user.set_password(password)
    user.save()
    return user
class UserSerialize(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class ProfileSerialize(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = '__all__'