from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import DeviceUser, ScanRecord, Object

@admin.register(DeviceUser)
class DeviceUserAdmin(UserAdmin):
    model = DeviceUser
    list_display = ('device_id', 'object_name', 'point_name', 'is_staff')

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
    list_display = ('user', 'device_id', 'point_name', 'scan_date', 'scan_time', 'card_name', 'card_surname', 'is_valid')
    ordering = ('-scan_date', '-scan_time')



@admin.register(Object)
class ObjectAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)