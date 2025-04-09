from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils.timezone import now


OBJECT_CHOICES = [
    ('choice1', 'choice1'),
    ('choice2', 'choice2'),
    ('choice3', 'choice3'),
]

class DeviceUserManager(BaseUserManager):
    def create_user(self, device_id, password=None, **extra_fields):
        if not device_id:
            raise ValueError('Device ID is required')

        user = self.model(device_id=device_id, **extra_fields)
        user.set_password(password)          
        user.save()
        return user


    def create_superuser(self, device_id, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(device_id, password, **extra_fields)

class DeviceUser(AbstractBaseUser, PermissionsMixin):
    device_id = models.CharField(max_length=50, unique=True)
    object_name = models.CharField(max_length=50, choices=OBJECT_CHOICES)
    point_name = models.CharField(max_length=100)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'device_id'
    REQUIRED_FIELDS = ['object_name', 'point_name']

    objects = DeviceUserManager()

    def __str__(self):
        return self.device_id

class ScanRecord(models.Model):
    user = models.ForeignKey(DeviceUser, on_delete=models.CASCADE)
    device_id = models.CharField(max_length=50)  
    object_name = models.CharField(max_length=50, choices=OBJECT_CHOICES, default='choice1')
    point_name = models.CharField(max_length=100)
    scan_date = models.DateField(default=now)
    scan_time = models.TimeField(default=now)
    card_name = models.CharField(max_length=100)
    card_surname = models.CharField(max_length=100)
    is_valid = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.device_id} - {self.card_name} {self.card_surname}"