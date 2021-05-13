# -*- coding: utf-8 -*-
__author__="Anil Kumar Gupta"
__copyright__="Copyright (©) 2017. ORDC. All rights reserved."
__credits__=["ORDC"]

# Django related dependencies
from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token


# Project Related dependencies
GENDER_CHOICES=(
        ('M', 'Male'),
        ('F', 'Female'),
        ('O','Other'),
    )

LOGIN_CHOICES=(
    (0, "Allow Concurrent Login (Required)"),
    (1, 'False'),
    (2, 'True')
)

ORG_TYPE = (
    (0, "Company"),
    (1, "Organisation")
)

class Role(models.Model):

    """ 'Staff','Supervisor','Sr Supervisor','Manager',
	'Sr Manager','Director,'Customer' 
    """
    code	 		           = models.CharField(max_length=50, unique=True, db_index=True)
    description 		       = models.CharField(max_length=150, blank=True, null=True)
    added_on 			       = models.DateTimeField(auto_now_add=True, db_index=True) 
    status 			           = models.FloatField(default=0,db_index=True)

    def __str__(self):
        return self.code


class DepartmentType(models.Model):
    code 	                   = models.CharField(max_length=50, unique=True, db_index=True)
    description                = models.CharField(max_length=150, blank=True, null=True)
    added_on 			       = models.DateTimeField(auto_now_add=True, db_index=True)
    status 			           = models.FloatField(default=0,db_index=True)
    
    def __str__(self):
        return self.code


class Department(models.Model):

    """
    'Account','Customer Service','Customer Service Accounts','Finance','HR', 'Hub','IT','Operations','Sale'
    """

    name 			           = models.CharField(max_length=150,blank=True, null=True)
    code 			           = models.CharField(max_length=150,unique=True, db_index=True)
    department_type 		   = models.ForeignKey(DepartmentType, null=True, on_delete=models.SET_NULL)
    added_on 			       = models.DateTimeField(auto_now_add=True, db_index=True)
    status 			           = models.FloatField(default=0,db_index=True)
    additonal_info_key 		   = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    additonal_info_value 	   = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
       return self.name

class Country(models.Model):
    name 			           = models.CharField(max_length=100)
    code 			           = models.CharField(max_length=50, unique=True)
    currency 			       = models.CharField(max_length=50,null=True, blank=True)
    currency_code 		       = models.CharField(max_length=50,null=True, blank=True)
    isd_code 			       = models.CharField(max_length=50, unique=True)
    continent 			       = models.CharField(max_length=50,null=True, blank=True)
    time_zone 			       = models.CharField(max_length=50,null=True, blank=True)
    status 			           = models.FloatField(default=1,db_index=True)
    added_on 			       = models.DateTimeField(auto_now_add=True,db_index=True)
    additonal_info_key 		   = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    additonal_info_value 	   = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return self.name


class State(models.Model):
    country 			       = models.ForeignKey(Country, null=True, on_delete=models.SET_NULL)
    name 			           = models.CharField(max_length=100)
    code 			           = models.CharField(max_length=50, unique=True)
    gst_service_code 		   = models.CharField(max_length=50, unique=True, null=True, blank =True)
    status 			           = models.FloatField(default=1,db_index=True)
    added_on 			       = models.DateTimeField(auto_now_add=True,db_index=True)
    additonal_info_key 		   = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    additonal_info_value 	   = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return self.name


class City(models.Model):
    state 			            = models.ForeignKey(State, null=True, on_delete=models.SET_NULL)
    name 			            = models.CharField(max_length=100)
    code 			            = models.CharField(max_length=50, unique=True)
    status 			            = models.FloatField(default=1,db_index=True)
    added_on 			        = models.DateTimeField(auto_now_add=True,db_index=True)
    additonal_info_key 		    = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    additonal_info_value 	    = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        return self.name


class ServiceCentre(models.Model):
    city 			            = models.ForeignKey(City, null=True, on_delete=models.SET_NULL)
    name 			            = models.CharField(max_length=100)
    code 			            = models.CharField(max_length=50, unique=True)
    email 		    	        = models.CharField(max_length=100, null=True, blank=True)
    phone 			            = models.CharField(max_length=20, null=True, blank=True)
    registration_number 	    = models.CharField(max_length= 50, null=True, blank=True)
    contact_person 		        = models.CharField(max_length=100, null=True, blank=True)
    person_email 		        = models.CharField(max_length=100, null=True, blank=True)
    person_mobile 		        = models.CharField(max_length=20, null=True, blank=True)
    landmark 			        = models.CharField(max_length=300, null=True, blank=True)
    address 			        = models.CharField(max_length=600, null=True, blank=True)
    pincode 			        = models.IntegerField(default=1,db_index=True, null=True, blank=True)
    status 			            = models.FloatField(default=1,db_index=True)
    added_on 			        = models.DateTimeField(auto_now_add=True,db_index=True)
    updated_on 			        = models.DateTimeField(auto_now=True,null=True, blank=True,db_index=True)
    additonal_info_key 		    = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    additonal_info_value 	    = models.CharField(max_length=200, null=True, blank=True)
    def __str__(self):
        return self.name
  
    def get_name_with_code(self):
        return self.name.encode('ascii', 'ignore') + " - " + str(self.code)
 
class Organisation(models.Model):
    name               		    = models.CharField(max_length=100)
    code                	    = models.CharField(max_length=30)
    org_type    	            = models.IntegerField(choices=ORG_TYPE, default=0)
    address			            = models.CharField(max_length=600,blank=True,null=True)
    city                	    = models.ForeignKey('City', null=True , on_delete=models.SET_NULL, related_name="org_city")
    pincode             	    = models.IntegerField(blank=True,null=True)
    activation_status   	    = models.BooleanField(blank=True)
    activation_date     	    = models.DateField(blank=True,null=True)
    contact_person      	    = models.CharField(max_length=100,blank=True,null=True) 
    contact_person_phone	    = models.IntegerField(blank=True,null=True)
    email	        	        = models.CharField(max_length=100,blank=True,null=True)
    gst_number			        = models.CharField(max_length=100,blank=True,null=True)
    gst_type			        = models.CharField(max_length=100,blank=True,null=True)
    added_on 			        = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_on 			        = models.DateTimeField(auto_now=True, db_index=True)
    status 			            = models.FloatField(default=0,db_index=True)
    additonal_info_key 		    = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    additonal_info_value        = models.CharField(max_length=200, null=True, blank=True)
    
    def __str__(self):
        return self.name 
    
    def get_as_company_detail(self):
        # Software operating org detail or software created by 
        company_detail={}
        company_detail['company_id'] = self.id
        company_detail['company_name'] = self.name
        company_detail['company_code'] = self.code
        company_detail['company_address'] = self.address
        company_detail['company_city'] = self.city.name
        company_detail['company_pincode'] = self.pincode
        company_detail['company_email'] = self.email
        company_detail['company_gst_number'] = self.gst_number
        return company_detail
    
    def get_as_org_detail(self):
        ## TODO  ## A Client have multiple baranches
        pass
        


class EmployeeMaster(models.Model):
    user 			            = models.OneToOneField(User, null=True, on_delete=models.SET_NULL)
    employee_code 		        = models.CharField(max_length=10, unique=True)
    firstname 			        = models.CharField(max_length=60)
    middle_name                 = models.CharField(max_length=100, null= True, blank= True)
    lastname 			        = models.CharField(max_length=60)
    organisation 		        = models.ForeignKey(Organisation, null=True, on_delete=models.SET_NULL)
    role 			            = models.ForeignKey(Role, null=True, on_delete=models.SET_NULL)
    department 			        = models.ForeignKey(Department, null=True, on_delete=models.SET_NULL)
    service_centre 		        = models.ForeignKey(ServiceCentre, null=True, on_delete=models.SET_NULL)
    email 			            = models.CharField(max_length=100, null=True, blank=True)
    mobile_number		        = models.CharField(max_length=60)
    login_active 		        = models.IntegerField(default=0)
    staff_status 		        = models.IntegerField(default=0) #0:perm, 1:temp, 2:deact 3: App User
    allow_concurent_login 	    = models.IntegerField(choices=LOGIN_CHOICES, default=0)
    query_limit 		        = models.IntegerField(default=50)
    added_on 			        = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_on 			        = models.DateTimeField(auto_now=True, db_index=True)
    login_status_app		    = models.BooleanField(default=False)
    login_status_web		    = models.BooleanField(default=False)
    status 			            = models.FloatField(default=0,db_index=True) ## 1:Active & verified
    additonal_info_key 		    = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    additonal_info_value        = models.CharField(max_length=200, null=True, blank=True)

    # def __str__(self):
    #     return self.firstname.encode('ascii', 'ignore') + " " + self.lastname.encode('ascii','ignore') + " - "+ str(self.employee_code)

    def get_name_with_email(self):
        return str(self.firstname) + " -  " + str(self.lastname) + " - " + str(self.email)

    def get_name_with_employee_code(self):
        return self.firstname.encode('ascii', 'ignore') + " - " + str(self.employee_code)

    def save(self,*args, **kwargs):
        if not self.query_limit:
            self.query_limit=50
        super(EmployeeMaster, self).save(*args, **kwargs)


class EmployeePersonalInfo(models.Model):
    employee			        = models.ForeignKey('EmployeeMaster', null=True, on_delete=models.SET_NULL)
    father_name                 = models.CharField(max_length=200,null= True, blank= True)
    mother_name                 = models.CharField(max_length=200, null= True, blank= True)
    date_of_birth               = models. DateField(null=True, blank=True)
    gender                      = models.CharField(max_length=30,null=True, blank=True)
    blood_group                 = models.CharField(max_length=10,null=True, blank=True)
    address                     = models.CharField(max_length=600, null=True, blank=True)
    mobile                      = models.IntegerField(null= True, blank= True)
    city                        = models.ForeignKey(City,null=True, on_delete=models.SET_NULL)
    state                       = models.ForeignKey(State,null=True, on_delete=models.SET_NULL)
    country                     = models.ForeignKey(Country,null=True, on_delete=models.SET_NULL)
    pincode                     = models.IntegerField(default=1,db_index=True, null=True, blank=True)
    kyc_id_name                 = models.CharField(max_length=50, null= True, blank= True) ## PAN CARD
    kyc_id                      = models.CharField(max_length=50, null= True, blank= True) ## PAN Number
    kyc_id_status               = models.FloatField(default=0,db_index=True) ## 1: Veryfied, 0:Not Verified
    kyc_adderess_name           = models.CharField(max_length=50, null= True, blank= True) ## ADHAAR CARD
    kyc_adderess                = models.CharField(max_length=50, null= True, blank= True) ## Adhaar Number
    kyc_adderess_status         = models.FloatField(default=0,db_index=True) ## 1: Veryfied, 0:Not Verified
	 
    # def __str__(self):
    #     return self.employee


class AccessToken(models.Model):
    token         		        = models.CharField(max_length=750, null=True, blank=True)
    mobile        		        = models.IntegerField(null=True, blank=True)
    email         		        = models.CharField(max_length=255, null=True, blank=True)
    latitude      		        = models.BooleanField(max_length=30, default=0, db_index=True)
    longitude     		        = models.BooleanField(max_length=30, default=0, db_index=True)
    ip_address    		        = models.CharField(max_length=20, null=True, blank=True, db_index=True)
    status        		        = models.IntegerField(default=1, db_index=True)
    added_on      		        = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_on    		        = models.DateTimeField(auto_now=True, db_index=True)
    

# class EmployeeLoginHistory(models.Model):
#     employee     		        = models.ForeignKey(EmployeeMaster, related_name='employee_history', null=True, on_delete=models.SET_NULL)
#     access_token     		    = models.ForeignKey(AccessToken, related_name='token_history', null=True, on_delete=models.SET_NULL)
#     status        		        = models.IntegerField(default=1, db_index=True)
#     added_on     		        = models.DateTimeField(auto_now_add=True, db_index=True)
     
class PasswordPeriod(models.Model):
    user                        = models.ForeignKey("EmployeeMaster", null=True, on_delete=models.SET_NULL)
    start_date                  = models.DateTimeField()
    end_date                    = models.DateTimeField() 

    def __str__(self):
	    return self.user 

class Address(models.Model):
    first_name 			        = models.CharField(max_length=50, blank=True)
    last_name 			        = models.CharField(max_length=50, blank=True)
    phone 			            = models.CharField(max_length=15, blank=True)
    email 			            = models.CharField(max_length=15, blank=True)
    company_name 		        = models.CharField(max_length=100, blank=True)
    address            		    = models.CharField(max_length=500, blank=True)
    city 			            = models.CharField(max_length=50, blank=True)
    area     			        = models.CharField(max_length=50, blank=True)
    pincode      		        = models.CharField(max_length=20, blank=True)
    state	 		            = models.ForeignKey(State, null=True, on_delete=models.SET_NULL)
    country			            = models.ForeignKey(Country, null=True, on_delete=models.SET_NULL)
    country_area		        = models.CharField(max_length=20, blank=True)

    @property
    def full_name(self):
        return '%s %s' % (self.first_name, self.last_name)

    def __str__(self):
        if self.company_name:
            return '%s - %s' % (self.company_name, self.full_name)
        return self.full_name

    def __repr__(self):
        return (
            'Address(first_name=%r, last_name=%r, company_name=%r, '
            'address=%r, city=%r, '
            'postal_code=%r, country=%r, country_area=%r, phone=%r)' % (
                self.first_name, self.last_name, self.company_name,
                self.address, self.city,
                self.pincode, self.country, self.country_area,
                self.phone))

    def __eq__(self, other):
        return self.as_data() == other.as_data()

    def get_copy(self):
        """Return a new instance of the same address."""
        return Address.objects.create(**self.as_data())

class EmployeeLoginHistory(models.Model):
    employee     		= models.ForeignKey(EmployeeMaster, related_name='employee_login_history', null=True, on_delete=models.SET_NULL)
    request_type 		= models.CharField(max_length=150,blank=True, null=True)
    app_version 		= models.CharField(max_length=50,blank=True, null=True)
    device_id 			= models.CharField(max_length=150,blank=True, null=True)
    device_type 		= models.CharField(max_length=150,blank=True, null=True)
    ip 			        = models.CharField(max_length=150,blank=True, null=True)
    app_id 			    = models.CharField(max_length=150,blank=True, null=True)
    imei 			    = models.CharField(max_length=150,blank=True, null=True)
    status        		= models.IntegerField(default=1, db_index=True)
    added_on     		= models.DateTimeField(auto_now_add=True, db_index=True)

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)

class UserOtp(models.Model):
    user    		    = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    otp 		        = models.CharField(max_length=150,blank=True, null=True)
    is_expired 		    = models.IntegerField(default=0,db_index=True, null=True, blank=True)
    create_at 			= models.DateTimeField(auto_now_add=True, db_index=True)



class Photo(models.Model):
	employee_code = models.CharField(max_length=256, blank=True, null=True)
	file = models.ImageField(upload_to='profile/')
	timestamp = models.DateTimeField(auto_now=True)
	updated = models.DateTimeField(auto_now_add=True)
