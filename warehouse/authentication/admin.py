from django.contrib import admin
from authentication.models import *

# Register your models here.
class RoleAdmin(admin.ModelAdmin):
    list_display = ('code', 'description', 'added_on', 'status')
    

class OrganisationAdmin(admin.ModelAdmin):
    list_display = ('name', 'code', 'address', 'gst_number', 'gst_type')


admin.site.register(Role, RoleAdmin)
admin.site.register(DepartmentType)
admin.site.register(Department)
admin.site.register(Country)
admin.site.register(State)
admin.site.register(City)
admin.site.register(ServiceCentre)
admin.site.register(Organisation, OrganisationAdmin)
admin.site.register(EmployeeMaster)
admin.site.register(EmployeePersonalInfo)
admin.site.register(PasswordPeriod)
admin.site.register(UserOtp)


