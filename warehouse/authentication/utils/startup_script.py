# -*- coding: utf-8 -*-
__author__ = "Anil Kumar Gupta"
__copyright__ = "Copyright (©) 2017. ORDC. All rights reserved."
__credits__ = ["ORDC"]

import os
import sys
#import django
#from warehouse.settings import BASE_DIR
#BASE_DIR = os.path.dirname(os.path.dirname(__file__))
BASE_DIR = os.path.abspath(__file__)
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
print("BASE_DIR",BASE_DIR)
BASE_DIR = "/home/ubuntu/web/ordc-warehouse/warehouse"
sys.path.append(BASE_DIR)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "warehouse.settings")
import django
django.setup()


class StartupScript:
    """
    StartupScript is class used to create intial data in masters
    """ 
    def create_country(self):
        c_data = data["COUNTRY"]
        state_data = data["STATE"]
        print ("country_data", country_data)
        for country_data in c_data:
            already_created =  Country.objects.filter(code=country_data["CODE"])
            if not already_created:
                c=Country.objects.create(name=country_data["NAME"], code=country_data["CODE"],
				currency=country_data["CURRENCY"],currency_code=country_data["CURRENCY_CODE"],
				isd_code=country_data["ISD_CODE"],continent=country_data["CONTINENT"],time_zone=country_data["TIME_ZONE"])
                print('{0} Created'.format(country_data["CODE"]))

            for st_data in state_data:
                already_created =  State.objects.filter(code=st_data["CODE"])
                if not already_created:
                    State.objects.create(country=c,name=st_data["NAME"],code=st_data["CODE"],gst_service_code=st_data["GST_CODE"])
         

    def create_state(self):
        state_data = data["STATE"]
        print(state_data)

    def create_city(self):
        city_data = data["CITY"]
        print(city_data)
        for c_data in city_data:
            already_created =  City.objects.filter(code=c_data["CODE"])
            if not already_created:
                st =  State.objects.get(code=c_data["STATE_CODE"])
                City.objects.create(state=st,name=c_data["NAME"],code=c_data["CODE"])
                print("City Created")

    def create_service_centre(self):
        s_data = data["SERVICE_CENTRE"]
        print(sc_data)
        for sc_data in s_data:
            already_created = ServiceCentre.objects.filter(code=sc_data["CODE"])
            if not already_created:
                c = City.objects.get(code=sc_data["CITY_CODE"])
                ServiceCentre.objects.create(city=c,
                                             name=sc_data["NAME"],
                                             code=sc_data["CODE"],
                                             sc_email=sc_data["SC_EMAIL"],
                                             sc_phone=sc_data["SC_PHONE"],
                                             registration_number=sc_data["REG"],
                                             contact_person=sc_data["CONT_PERSON"],
                                             person_email=sc_data["PERSON_EMAIL"],
                                             person_mobile=sc_data["PERSON_MOBILE"],
                                             landmark=sc_data["LANDMARK"],
                                             address1=sc_data["ADD1"],
                                             address2=sc_data["ADD2"],
                                             address3=sc_data["ADD3"],
                                             pincode=sc_data["PINCODE"])

    def create_role(self):
        rolle_data = data["ROLE"]
        print(role_data) 

    def create_department_type(self):
        dt_data = data["DEPARTMENT_TYPE"]
        print(dt_data)

    def create_department(self):
        d_data = data["DEPARTMENT"]
        print(d_data)

    def create_employee_master(self):
        emp_data = data["EMPLOYEE"]
        print(emp_data)
    
    def create_user_master(self):
        from django.contrib.auth.models import User 
        ##TODO Create User dynamically and then load Employee
        u = User.objects.create(email="admin@gmail.com", first_name="Admin", last_name="ORDC", password="1234", username="admin@gmail.com")
        u.set_password("admin@1234")
        u.is_superuser=True
        u.is_staff=True
        u.save()
        u = User.objects.create(email="staff@gmail.com", first_name="Staff", last_name="ORDC", password="1234", username="staff@gmail.com")
        u.set_password("admin@1234")
        u.save()
        print("User Created")


data = {"ROLE":[{"ROLE_CODE":"ADMIN","ROLE_DESC":"Admin"},
                {"ROLE_CODE":"DIRECTOR","ROLE_DESC":"Director"},
		{"ROLE_CODE":"MANAGER","ROLE_DESC":"Manager"},
		{"ROLE_CODE":"CUSTOMER","ROLE_DESC":"Customer"},
		{"ROLE_CODE":"SRSUPERVISOR","ROLE_DESC":"Sr.Supervisor"},
		{"ROLE_CODE":"","ROLE_DESC":"Staff"}
		],
        "DEPARTMENT_TYPE":[{"DEPT_TYPE_CODE":"ACCOUNT","DEPT_TYPE_DESC":"Account"},
			   {"DEPT_TYPE_CODE":"OPERATION","DEPT_TYPE_DESC":"Operation"},
		],
	"DEPARTMENT":[{"CODE":"AC","DESC":"Account"},
    		      {"CODE":"CS","DESC":"Customer Service"},
    		      {"CODE":"CSAC","DESC":"Customer Service Account"},
    		      {"CODE":"FIN","DESC":"Finance"},
    		      {"CODE":"HR","DESC":"Human Resource"},
    		      {"CODE":"IT","DESC":"Information Technology"},
    		      {"CODE":"OP","DESC":"Operations"},
    		      {"CODE":"SALE","DESC":"Sale"},
		],
	"COUNTRY":[{"NAME":"India","CODE":"IN","CURRENCY":"Indian Rupee","CURRENCY_CODE":"R","ISD_CODE":"+91","CONTI":"Asia","TIME_ZONE":"+5.30 GMT"}
		],
	"STATE":[{"NAME":"Delhi","CODE":"DL","GST_CODE":"01","COUNTRY_CODE":"IN"}
		],
	"CITY":[{"NAME":"New Delhi","CODE":"NDLS","STATE_CODE":"DL"}
		],
	"SERVICE_CENTRE":[{"CITY_CODE":"DL","NAME":"ORDC-SC","CODE":"ORDC","SC_EMAIL":"info@ordc.in","SC_PHONE":"9540796539","REG":"REG-03545456","CONT_PERSON":"Anil","PERSON_EMAIL":"anil.gupta@ordc.in","PERSON_MOBILE":"9540796539","LANDMARK":"Near to Airport","PINCODE":"110001","ADD1":"Add1","ADD2":"Add2","ADD3":"Add3"}
		],
	"ORGANISATION":[{"NAME":"ORG-ORDC-WAREHOUSE","CODE":"ORG-ORDC-WMS"}],
	"EMPLOYEE":[{"USER":"admin@ordc.in","EMP_CODE":"ORDC10000","FIRST_NAME":"Anil","MIDDLE_NAME":"Kumar", "LAST_NAME":"Gupta","EMAIL":"admin@ordc.in","MOBILE":"9540796539"}],
        
	}


if __name__=="__main__":
    StartupScript().create_user_master()
    ##Storage Location Create
    from wms_utility.process.wms_location_process import create_storage_location
    create_storage_location()
