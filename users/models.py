from datetime import datetime, timedelta
import random
import uuid

from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken

from shared.models import BaseModel



ORDINARY_USER, MANAGER, ADMIN = ('ordinary_user', 'manager', 'admin')
NEW, CODE_VERIFIED, DONE, PHOTO_STEP = ('new', 'code_verified', 'done', 'photo_step')


class User(AbstractUser, BaseModel):
    USER_ROLES = (
        (ORDINARY_USER, ORDINARY_USER),
        (MANAGER, MANAGER),
        (ADMIN, ADMIN),
    )
    AUTH_STATUS = (
        (NEW, NEW),
        (CODE_VERIFIED, CODE_VERIFIED),
        (DONE, DONE),
        (PHOTO_STEP, PHOTO_STEP),
    )
    user_roles = models.CharField(max_length=31, choices=USER_ROLES, default=ORDINARY_USER)
    auth_status = models.CharField(max_length=31, choices=AUTH_STATUS, default=NEW)  # registratsiya bosqichlari
    phone = models.CharField(max_length=13, null=True, blank=True, unique=True)
    photo = models.ImageField(upload_to='user_photos', null=True, blank=True,
                              validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'heic', 'heif'])])

    def __str__(self):
        return self.username
#
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def create_verify_code(self):
        code = "".join(str(random.randint(0,100) // 10) for _ in range(4))
        UserConfirmation.objects.create(
            user_id=self.id,
            code=code
        )
        return code


    def check_username(self):
        if not self.username:
            temp_username = f"instagram-{uuid.uuid4().__str__().split('-')[-1]}"
            while User.objects.filter(username=temp_username):
                temp_username=f"{temp_username}{random.randint(0,9)}"
            self.username = temp_username

    def check_pass(self):
        if not self.password:
            temp_password = f"password-{uuid.uuid4().__str__().split('-')[-1]}"
            self.password = temp_password

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            'access': str(refresh.access_token),
            'refresh_token': str(refresh)
        }

    def save(self, *args, **kwargs):
        self.check_username()
        self.check_pass()
        self.hashing_password()
        super(User, self).save(*args, **kwargs)





PHONE_EXPIRE = 2

class UserConfirmation(BaseModel):
    code = models.CharField(max_length=4)
    user = models.ForeignKey('users.User', models.CASCADE, related_name='verify_codes')
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user.__str__())

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def save(self, *args, **kwargs):
        self.expiration_time = datetime.now() + timedelta(minutes=PHONE_EXPIRE)
        super(UserConfirmation, self).save(*args, **kwargs)
