from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils.timezone import now


class Object(models.Model):
    name = models.CharField(max_length=50, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


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
    object_name = models.ForeignKey(
        Object, on_delete=models.SET_NULL, related_name='users', null=True, blank=True
    )
    point_name = models.CharField(max_length=100)
    created_date = models.DateTimeField(null=True, blank=True)  # Allow null/blank for manual creation
    created_time = models.TimeField(null=True, blank=True)  # Allow null/blank for manual creation
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'device_id'

    objects = DeviceUserManager()

    def save(self, *args, **kwargs):
        # Set created_date and created_time only when the object is created
        if not self.pk:  # Check if the object is being created
            self.created_date = now()
            self.created_time = now().time()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.device_id


class ScanRecord(models.Model):
    user = models.ForeignKey(
        DeviceUser, on_delete=models.CASCADE, related_name='scan_records'
    )  
    object_name = models.CharField(max_length=50)
    point_name = models.CharField(max_length=100)
    scan_date = models.DateField(default=now)
    scan_time = models.TimeField(default=now)
    card_name = models.CharField(max_length=100, null=True, blank=True)
    card_surname = models.CharField(max_length=100, null=True, blank=True)
    card_response = models.CharField(max_length=100, null=True, blank=True)
    is_valid = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.device_id} - {self.card_name} {self.card_surname}"

class ClockInAndOut(models.Model):
    ACTION_CHOICES = [
        ('clock_in', 'Clock In'),
        ('clock_out', 'Clock Out'),
    ]
    name = models.CharField(max_length=50,null=True,blank=True) 
    object_name = models.CharField(max_length=50, null=True, blank=True)
    birthyear = models.CharField(max_length=10,null=True,blank=True)
    surname = models.CharField(max_length=10,null=True,blank=True)
    card_response = models.CharField(max_length=100, null=True, blank=True)
    clock_in_time = models.DateTimeField(auto_now_add=True)
    clock_out_time = models.DateTimeField(null=True, blank=True)
    action_type = models.CharField(max_length=10, choices=ACTION_CHOICES, default='clock_in')

    def __str__(self):
        return f"{self.name} - {self.action_type} at {self.clock_in_time}"

    class Meta:
        ordering = ['-clock_in_time', '-clock_out_time']