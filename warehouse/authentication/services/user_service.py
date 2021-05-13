# -*- coding: utf-8 -*-
__author__ = "Anil Kumar  Gupta"
__copyright__ = "Copyright (©) 2017. ORDC. All rights reserved."
__credits__ = ["ORDC"]


#Python Related dependencies
import json
import logging
logger = logging.getLogger(__name__)
# Django related dependencies
from django.contrib.auth.models import User
from django.db.models import Q
from django.db import transaction
from django.contrib.auth import authenticate



# Project Related dependencies
from authentication.models import EmployeeMaster, Role, EmployeePersonalInfo, City ,Organisation, Country, State
from authentication.utils.common_utility import CommonUtility



class UserService():
    
    def user_detail(self, requested_data):
        """ 
        Take username and role id as input and return result with employee informations
        """
        resp = {}
        emp_code = requested_data.get('employee_code')
        mobile_number = requested_data.get('mobile_number')
        emp_details = EmployeeMaster.objects.filter(Q(employee_code=emp_code) | Q(mobile_number=mobile_number))
        if emp_details:
            employee_detail_data = {}
            for emp in emp_details:
                employeepersonalinfo_list = emp.employeepersonalinfo_set.all()
                data = {}
                kyc_list = []
                serviceable_area_list = []
                try:
                    role = emp.role.code
                except:
                    role = emp.role
                company_id = ""
                company_name = ""
                company_poc = ""
                company_phone = ""
                company_email = "" 
                company_company_website = ""
                company_address = ""
                company_city = ""
                company_state = ""
                company_country = ""
                company_pincode = ""
                if emp.organisation:
                    company_id = emp.organisation.id
                    company_name = emp.organisation.name
                    company_poc = emp.organisation.contact_person
                    company_phone = emp.organisation.contact_person_phone
                    company_email = emp.organisation.email 
                    company_company_website = ""
                    company_address = emp.organisation.address
                    company_city = emp.organisation.city.name
                    company_state = ""
                    company_country = ""
                    company_pincode = emp.organisation.pincode

                city_id = ""
                city_name = ""
                city_code = ""
                state_id = ""
                state_name = ""
                state_code = ""
                country_id = ""
                country_name = ""
                country_code = ""
                blood_group = ""
                pincode = ""
                kyc_id_name = ""
                kyc_id = ""
                kyc_id_status = ""
                kyc_adderess = ""
                kyc_adderess_name = ""
                kyc_adderess_status = ""
                if employeepersonalinfo_list:
                    if employeepersonalinfo_list[0].city:
                        city_id = employeepersonalinfo_list[0].city.id
                        city_name = employeepersonalinfo_list[0].city.name
                        city_code = employeepersonalinfo_list[0].city.code
                    if employeepersonalinfo_list[0].state:
                        state_id = employeepersonalinfo_list[0].state.id
                        state_name = employeepersonalinfo_list[0].state.name
                        state_code = employeepersonalinfo_list[0].state.code
                    if employeepersonalinfo_list[0].country:
                        country_id = employeepersonalinfo_list[0].country.id
                        country_name = employeepersonalinfo_list[0].country.name
                        country_code = employeepersonalinfo_list[0].country.code
                
                    blood_group = employeepersonalinfo_list[0].blood_group
                    pincode = employeepersonalinfo_list[0].pincode
                    kyc_adderess = employeepersonalinfo_list[0].kyc_adderess
                    kyc_adderess_name = employeepersonalinfo_list[0].kyc_adderess_name
                    kyc_adderess_status = employeepersonalinfo_list[0].kyc_adderess_status
                    kyc_id_name = employeepersonalinfo_list[0].kyc_id_name
                    kyc_id = employeepersonalinfo_list[0].kyc_id
                    kyc_id_status = employeepersonalinfo_list[0].kyc_id_status

                data['general_details'] = {"employee_id":emp.id,"employee_code": emp.employee_code,"firstname":emp.firstname,"lastname": emp.lastname, "added_on": str(emp.added_on), "is_active": emp.status, "active_from":"", "blood_group":blood_group}
                data['parmanent_address'] = {"street_address": kyc_adderess, "landmark": "", "city_id": city_id, "city_name": city_name, "city_code": city_code, "state_id": state_id, "state_name": state_name, "state_code": state_code, "country_id": country_id, "country_name": country_name, "country_code": country_code, "pincode": pincode}
                data['communication_address'] = {"street_address": kyc_adderess, "landmark": "", "city_id": city_id, "city_name": city_name, "city_code": city_code, "state_id": state_id, "state_name": state_name, "state_code": state_code, "country_id": country_id, "country_name": country_name, "country_code": country_code, "pincode": pincode}
                data['contact_detail'] = {"mobile_number": emp.mobile_number, "email": emp.email, "emergency_contact_person": "", "emergency_mobile": "",}
                data['serviceable_area'] = serviceable_area_list
                data['company_detail'] = {"company_id":company_id,"name":company_name, "company_poc": company_poc, "company_email": company_email, "company_phone": company_phone, "company_website": "", "address": company_address, "city": company_city, "state": company_state, "pincode": company_pincode, "country": company_country}
                data['kyc_detail'] = {"kyc_id_name": kyc_id_name, "kyc_id": kyc_id, "kyc_id_status": kyc_id_status,"kyc_adderess_name": kyc_adderess_name, "kyc_adderess": kyc_adderess, "kyc_adderess_status": kyc_adderess_status}
                employee_detail_data[emp.employee_code]=data
            resp["is_success"] = 'Success'
            resp["status_code"] = 200
            resp["message"] = 'You Fetched Employee Details Successfully'
            resp["result"] = employee_detail_data
        else:
            resp["is_success"] =  'Failed'
            resp["status_code"] = 200
            resp["message"] = 'No Record Found'
            resp["result"] = {}
            
        logger.error(resp["message"])
        return resp

    def user_register(self, requested_data):
        """ 
        Take user information as input e.g username,password,firstname etc.
        Store user information into respective tables and return result with proper info message
        """
        resp = {}
        pwd = requested_data['password']
        confirm_pwd = requested_data['confirm_password']
        ## No need to show password in response
        del requested_data['password']
        del requested_data['confirm_password']
        if requested_data.get("username"):
            # Validate Unique User
            if User.objects.filter(username=requested_data["username"].strip()):
                resp["is_success"] =  'Failed'
                resp["status_code"] = 200
                resp["message"] = 'Username "{0}" is already in use.'.format(requested_data["username"])
                resp["result"] = requested_data
            else:
                # Validate Password and Confirm password
                if pwd != confirm_pwd:
                    resp["is_success"] =  'Failed'
                    resp["status_code"] = 200
                    resp["message"] = 'Password and Confirm Password does not match'
                    resp["result"] = requested_data
                    return resp
                ## TODO we need to validate mobile number ie. number of digit and country code 
                if EmployeeMaster.objects.filter(mobile_number=requested_data["mobile_number"].strip()).count():
                    resp["is_success"] =  'Failed'
                    resp["status_code"] = 200
                    resp["message"] = 'Mobile No "{0}" is already in use.'.format(requested_data["mobile_number"])
                    resp["result"] = requested_data
                    return resp
                # Validate Password Policy
                is_password_valid = CommonUtility().validate_password_strength(pwd)
                #print("is_password_valid", is_password_valid)
                if  is_password_valid == 'success':
                    try:
                        # saving user info into user Table
                        with transaction.atomic():
                            user = User()
                            user.username = requested_data["username"]
                            user.set_password(pwd)
                            user.is_staff = True
                            user.save()
                            # deleting usename and password from request_data
                            del requested_data["username"]
                            # saving user info into  EmployeeMaster Table
                            if not requested_data["user_type"]:
                                requested_data["role_id"] = 1
                            else:
                                roles = Role.objects.filter(code=requested_data["user_type"]).values('id')
                                for role in roles:
                                    requested_data["role_id"] = int(role['id'])
                                
                            del requested_data["user_type"]
                            employee = EmployeeMaster(**requested_data)
                            employee.user_id = user.pk
                            requested_data["employee_code"] =  CommonUtility().generate_code('EMP', user.pk)
                            employee.employee_code = requested_data["employee_code"]
                            employee.save()
                            resp["is_success"] = 'Success'
                            resp["status_code"] = 200
                            resp["message"] = "You have been successfully registered"
                            resp["result"] = requested_data
                    except Exception as e:
                        resp["is_success"] =  'Failed'
                        resp["status_code"] = 200
                        resp["message"] = str(e)
                        resp["result"] = requested_data
                else:
                    resp["is_success"] =  'Failed'
                    resp["message"] = is_password_valid
                    resp["status_code"] = 200
                    resp["result"] = requested_data
        else:
            resp["is_success"] =  'Failed'
            resp["status_code"] = 200
            resp["message"] = "Username can not be blank"
            resp["result"] = requested_data
        logger.error(resp["message"])
        return resp
    
    def update_profile(self, requested_data):

        """ 
        Take user informattion which to be updated and return result with updated values
        """
        resp = {}
        error_list = []
        kyc_list =[]
        emp_code = list(requested_data.keys())[0]
        if emp_code:
            # emp_code = requested_data['general_details']['employee_code']
            try:
                emp_details = EmployeeMaster.objects.get(employee_code=emp_code)
            except EmployeeMaster.DoesNotExist:
                emp_details = False
            if emp_details:
                emp_id = emp_details.id
                emp_master_list = ['employee_code', 'firstname', 'lastname', 'mobile_number', 'email','is_active','company_id']
                emp_master_dict = {}
                emp_personal_info_list = ['blood_group','city_id','state_id', 'pincode','country_id','street_address','kyc_id_name', 'kyc_id', 'kyc_id_status', 'kyc_adderess_name','kyc_adderess', 'kyc_adderess_status']
                emp_personal_info_dict = {}
                emp_personal_info_dict['employee_id'] = emp_id
                for key, value in requested_data[emp_code]['general_details'].items():
                    if key in emp_master_list:
                        if key == 'is_active':
                            emp_master_dict['status'] = value
                        else:
                            emp_master_dict[key] = value
                    elif key == 'blood_group':
                        emp_personal_info_dict['blood_group'] = value

                for key, value in requested_data[emp_code]['company_detail'].items():
                    if key == 'company_id':
                        if value !='' or None:
                            emp_master_dict['organisation'] = value

                for key, value in requested_data[emp_code]['parmanent_address'].items():
                    if key in emp_personal_info_list:
                        if key =='street_address':
                            emp_personal_info_dict['kyc_adderess'] = value
                        elif key =='city_id':
                            emp_personal_info_dict['city_id'] = value
                        elif key =='state_id':
                            emp_personal_info_dict['state_id'] = value
                        elif key =='country_id':
                            emp_personal_info_dict['country_id'] = value
                        else:
                            emp_personal_info_dict[key] = value
                for key, value in requested_data[emp_code]['contact_detail'].items():
                    if key in emp_master_list:
                        emp_master_dict[key] = value
                for key, value in requested_data[emp_code]['kyc_detail'].items():
                    if key in emp_personal_info_list:
                        emp_personal_info_dict[key] = value
                if  error_list:
                    resp["is_success"] =  'Failed'
                    resp["status_code"] = 200
                    resp["message"] = error_list
                    resp["result"] = requested_data
                else:
                    try:
                        with transaction.atomic():
                            emp_details = EmployeeMaster.objects.filter(employee_code=emp_code).update(**emp_master_dict)
                            try:
                                emp_info = EmployeePersonalInfo.objects.get(employee_id=emp_id)
                            except EmployeePersonalInfo.DoesNotExist:
                                emp_info = False
                            if emp_info:
                                del emp_personal_info_dict['employee_id']
                                emp_info_details = EmployeePersonalInfo.objects.filter(employee_id=emp_id).update(**emp_personal_info_dict)
                            else:
                                emp_info_details = EmployeePersonalInfo(**emp_personal_info_dict)
                                emp_info_details.save()
                            resp["is_success"] = 'Success'
                            resp["status_code"] = 200
                            resp["message"] = 'Profile Updated Successfully'
                            resp["result"] = requested_data
                    except Exception as e:
                        resp["is_success"] =  'Failed'
                        resp["status_code"] = 500
                        resp["message"] = str(e)
                        resp["result"] = requested_data
            else:
                resp["is_success"] =  'Failed'
                resp["status_code"] = 200
                resp["message"] = 'No record found for given employee_code'
                resp["result"] = requested_data
        else:
            resp["is_success"] =  'Failed'
            resp["status_code"] = 200
            resp["message"] = 'You must provide employee_code'
            resp["result"] = requested_data
        logger.error(resp["message"])
        return resp

    def user_action(self, requested_data):
        """
        Activate or  Deactivate employee based on action type
        """
        resp = {}
        try:
            emp_details = EmployeeMaster.objects.get(employee_code=requested_data["employee_code"])
        except EmployeeMaster.DoesNotExist:
            emp_details = False
        if emp_details:

            if requested_data["action_type"]=="ACTIVATE":
                status = 1
                msg = 'You have successfully changed status as active'
            elif requested_data["action_type"]=="DEACTIVATE":
                status = 0
                msg = 'You have successfully changed status as deactive'
            else:
                status = 'unknown'

            if  status != 'unknown':
                try:
                    EmployeeMaster.objects.filter(employee_code=requested_data["employee_code"]).update(status=status)
                    resp["is_success"] =  'Success'
                    resp["status_code"] = 200
                    resp["message"] = msg
                    resp["result"] = requested_data
                except Exception as e:
                    resp["is_success"] =  'Failed'
                    resp["status_code"] = 500
                    resp["message"] = str(e)
                    resp["result"] = requested_data
            else:
                resp["is_success"] =  'Failed'
                resp["status_code"] = 401
                resp["message"] = 'Invalid action type'
                resp["result"] = requested_data
        else:
            resp["is_success"] =  'Failed'
            resp["status_code"] = 200
            resp["message"] = 'No record found for given employee_code'
            resp["result"] = requested_data
        logger.error(resp["message"])  
        return resp
    
    def update_password(self,requested_data):
        """ Validate old password and new password and update new password"""
        resp = {}
        username = requested_data['user_name']
        old_pwd = requested_data['old_password']
        pwd = requested_data['new_password']
        confirm_pwd = requested_data['confirm_password']
        user = authenticate(username=username, password=old_pwd)
        if user is not None:
            if pwd != confirm_pwd:
                resp["is_success"] =  'Failed'
                resp["status_code"] = 200
                resp["message"] = 'Password and Confirm Password does not match'
                resp["result"] = {}
            else:
                # Validate Password Policy
                is_password_valid = CommonUtility().validate_password_strength(pwd)
                if  is_password_valid == 'success':
                    try:
                        user.set_password(pwd)
                        user.save()

                        resp["is_success"] =  'Success'
                        resp["status_code"] = 200
                        resp["message"] = 'Your password has been reset successfully!'
                        resp["result"] = {}
                    except Exception as e:
                        resp["is_success"] =  'Failed'
                        resp["status_code"] = 200
                        resp["message"] = str(e)
                        resp["result"] = {}
                else:
                    resp["is_success"] =  'Failed'
                    resp["status_code"] = 200
                    resp["message"] = is_password_valid
                    resp["result"] = {}
        else:
            resp["is_success"] =  'Failed'
            resp["status_code"] = 200
            resp["message"] = 'Invalid user or password'
            resp["result"] = {}
        logger.error(resp["message"])  
        return resp
