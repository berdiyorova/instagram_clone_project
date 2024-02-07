import phonenumbers
from decouple import config
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound
import re

from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken
from twilio.rest import Client

from .models import User, NEW, CODE_VERIFIED, DONE, PHOTO_STEP

username_regex = re.compile(r"^[a-zA-z0-9_.-]+$")
f_l_name_regex = re.compile(r"(^[a-zA-Z']{3,30}\s*)+")



class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    auth_status = serializers.CharField(read_only=True, required=False)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            'id',
            'auth_status'
        )


    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        code = user.create_verify_code()
        send_phone_code(user.phone, code)
        user.save()
        return user


    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('phone_number'))
        phone_number = phonenumbers.parse(user_input)
        if phonenumbers.is_valid_number(phone_number):
            data = {
                'phone': user_input,
            }

        else:
            data = {
                'success': False,
                'message': 'You must send phone number'
            }
            raise ValidationError(data)
        return data

    def validate_phone_number(self, value):
        value = value
        if value and User.objects.filter(phone=value).exists():
            data = {
                'success': False,
                'message': "Bu raqam allaqachon ishlatilgan"
            }
            raise ValidationError(data)
        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())
        return data




def send_phone_code(phone, code):
    account_sid = config('account_sid')
    auth_token = config('auth_token')
    client = Client(account_sid, auth_token)
    client.message.create(
        body=f"Sizning tasdiqlash kodingiz:  {code}\n",
        from_="+998993336565",
        to=f"{phone}"
    )






class ChangeUserInformation(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)


    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)
        if password != confirm_password:
            raise ValidationError(
                {
                    'message': 'Parol va tasdiqlash paroli mos kelmayapti'
                }
            )
        if password and confirm_password:
            validate_password(password)
            validate_password(confirm_password)

        return data


    def validate_username(self, username):
        if len(username) < 5 or len(username) > 30:
            raise ValidationError({
                "message": "Username uzunligi 5 tadan  kam, 30 tadan ko'p bo'lmasligi kerak"
            })
        if username.isdigit():
            raise ValidationError({
                'message': "Username faqat raqamlardan iborat bo'lmasligi kerak"
            })
        return username


    def validate_first_name(self, first_name):
        if not re.fullmatch(f_l_name_regex, first_name):
            raise ValidationError({
                'message': "Ismingizni to'g'ri kiriting"
            })
        return first_name


    def validate_last_name(self, last_name):
        if not re.fullmatch(f_l_name_regex, last_name):
            raise ValidationError({
                'message': "Familiyangizni to'g'ri kiriting"
            })
        return last_name


    def update(self, user, validated_data):
        user.first_name = validated_data.get('first_name', user.first_name)
        user.last_name = validated_data.get('last_name', user.last_name)
        user.username = validated_data.get('username', user.username)
        user.password = validated_data.get('password', user.password)

        if validated_data.get('password'):
            user.set_password(validated_data.get('password'))

        if user.auth_status == CODE_VERIFIED:
            user.auth_status = DONE

        user.save()
        return user





class LoginSerializer(TokenObtainPairSerializer):
    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['user_input'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(required=False, read_only=True)

    def auth_validate(self, data):
        user_input = data.get('user_input')
        if self.check_input_type(user_input) == 'username':
            username = user_input
        elif self.check_input_type(user_input) == 'phone':
            user = self.get_user(phone=user_input)
            username = user.username
        else:
            data = {
                'success': False,
                'message': 'Username yoki telefon raqamingizni kiriting'
            }
            raise ValidationError(data)

        authentication_kwargs = {
            self.username_field: username,
            'password': data['password']
        }
        current_user = User.objects.filter(username__iexact=username).first()
        if current_user is not None and current_user.auth_status in [NEW, CODE_VERIFIED]:
            raise ValidationError({
                'success': False,
                'message': "Siz ro'yxatdan to'liq o'tmagansiz"
            })
        user = authenticate(**authentication_kwargs)
        if user is not None:
            self.user = user
        else:
            raise ValidationError({
                'success': False,
                'message': 'Kechirasiz, siz kiritgan login yoki parol noto\'g\'ri. Iltimos, tekshirib qaytadan kiriting.'
            })


    @staticmethod
    def check_input_type(user_input):
        phone_number = phonenumbers.parse(user_input)
        if phonenumbers.is_valid_number(phone_number):
            user_input = 'phone'

        elif re.fullmatch(username_regex, user_input):
            user_input = 'username'
        else:
            data = {
                "success": False,
                "message": "Ma'lumot noto'g'ri kiritildi"
            }
            raise ValidationError(data)
        return user_input


    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [DONE, PHOTO_STEP]:
            raise PermissionDenied("Siz login qila olmaysiz, ruxsatingiz yo'q.")
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['full_name'] = self.user.full_name
        return data


    def get_user(self, **kwargs):
        users = User.objects.filter(**kwargs)
        if not users.exists():
            raise ValidationError({
                'message': 'Account topilmadi.'
            })
        return users.first()



class LoginRefreshSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        access_token_instance = AccessToken(data['access'])
        user_id = access_token_instance['user_id']
        user = get_object_or_404(User, id=user_id)
        update_last_login(None, user)
        return data



class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()




class ForgotPasswordSerializer(serializers.Serializer):
    phone_number = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        phone_number = attrs.get('phone_number', None)
        if phone_number is None:
            raise ValidationError(
                {
                    "success": False,
                    'message': "Telefon raqami kiritilishi shart!"
                }
            )
        user = User.objects.filter(phone=phone_number)
        if not user.exists():
            raise NotFound(detail="User not found")
        attrs['user'] = user.first()
        return attrs



class ResetPasswordSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    password = serializers.CharField(min_length=8, required=True, write_only=True)
    confirm_password = serializers.CharField(min_length=8, required=True, write_only=True)

    class Meta:
        model = User
        fields = (
            'id',
            'password',
            'confirm_password'
        )

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('password', None)
        if password != confirm_password:
            raise ValidationError(
                {
                    'success': False,
                    'message': "Parol va tasdiqlash paroli bir xil emas"
                }
            )
        if password:
            validate_password(password)
        return data

    def update(self, instance, validated_data):
        password = validated_data.pop('password')
        instance.set_password(password)
        return super(ResetPasswordSerializer, self).update(instance, validated_data)
