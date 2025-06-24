from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import DeviceUser, ScanRecord, Object, ClockInAndOut

@admin.register(DeviceUser)
class DeviceUserAdmin(UserAdmin):
    model = DeviceUser
    list_display = ('id','device_id', 'object_name', 'point_name','created_date','created_time', 'is_active', 'is_staff')
    search_fields = ('device_id', 'object_name__name', 'point_name')

    fieldsets = (
        (None, {'fields': ('device_id', 'password')}),
        ('Personal info', {'fields': ('object_name', 'point_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser','user_permissions')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('device_id', 'object_name', 'point_name', 'password1', 'password2'),
        }),
    )

    ordering = ('device_id',)

    def save_model(self, request, obj, form, change):
        password = form.cleaned_data.get("password1")
        if password:
            obj.set_password(password)
        super().save_model(request, obj, form, change)


@admin.register(ScanRecord)
class ScanRecordAdmin(admin.ModelAdmin):
    list_display = ('id','user', 'object_name', 'point_name', 'scan_date', 'scan_time', 'card_name', 'card_surname', 'is_valid')
    search_fields = ('user__device_id', 'object_name', 'point_name', 'card_name', 'card_surname')
    list_filter = ('is_valid', 'scan_date')
    ordering = ('-scan_date', '-scan_time')


@admin.register(Object)
class ObjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at')
    search_fields = ('name',)


@admin.register(ClockInAndOut)
class ClockAdmin(admin.ModelAdmin):
    list_display = ('id', 'name','surname','birthyear', 'object_name', 'clock_in_time', 'clock_out_time', 'action_type')
    list_filter = ('action_type', 'clock_in_time', 'clock_out_time')
    ordering = ('-clock_in_time',)
    search_fields = ('user__device_id', 'object_name', 'point_name')
