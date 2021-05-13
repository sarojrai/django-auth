# -*- coding: utf-8 -*-
__author__ = "Anil Kumar  Gupta"
__copyright__ = "Copyright (©) 2017. ORDC. All rights reserved."
__credits__ = ["ORDC"]
#  Python module and packages
import json
import logging
LOGGER = logging.getLogger(__name__)
from datetime import datetime, timedelta

# # Django module and packages
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.db import transaction
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.views import ObtainAuthToken

# # Project related module and packages
from authentication.services.user_service import UserService
from authentication.models import EmployeeMaster, EmployeeLoginHistory, UserOtp
from authentication.utils.common_utility import CommonUtility



# Global Variable
STATUS = "status"
STATUS_CODE = "status_code"
MESSAGE = "message"
RESULT = "result"
SUCCESS = "Success"
FAILED = "Failed"

class CustomAuthToken(ObtainAuthToken):
    """ Fetching token
    """
    def post(self, request):
        """ post username for fetching token """
    
        response = {
            STATUS: FAILED,
            STATUS_CODE: 401,
            MESSAGE: "Invalid User",
            RESULT: {}}
        requested_data = json.loads(request.body)
        user_name = requested_data['username']
        try:
            user = User.objects.get(username=user_name)
        except User.DoesNotExist:
            user = False
        if user:
            token, created = Token.objects.get_or_create(user=user)
            response[STATUS] = 'Success'
            response[STATUS_CODE] = 200
            response[MESSAGE] = 'Token Fetched successfully'
            response[RESULT] = {'token': token.key}
        response = json.dumps(response)
        return HttpResponse(response, content_type="application/json")

@api_view(["POST"])
@csrf_exempt
def user_registration(request):
    """
    Take user information as input for user registration and return result with status code
    """
    response = {
        STATUS: FAILED,
        STATUS_CODE: 400,
        MESSAGE: "Something went wrong !!",
        RESULT: {}}
    requested_data = json.loads(request.body)
    resp = UserService().user_register(requested_data)
    if resp.get("is_success"):
        response[STATUS] = resp.get("is_success")
        response[STATUS_CODE] = resp.get(STATUS_CODE)
        response[MESSAGE] = resp.get(MESSAGE)
        response[RESULT] = resp.get(RESULT)
    response = json.dumps(response)
    return HttpResponse(response, content_type="application/json")


@csrf_exempt
def login_user(request):
    """
    Take username and password as input and handles both authentication and authorization
    """
    response = {
        STATUS: FAILED,
        STATUS_CODE: 400,
        MESSAGE: "Something went wrong !!",
        RESULT: {}}
    requested_data = json.loads(request.body)
    user_name = requested_data.get('username')
    password = requested_data.get('password')
    if user_name == "" or password == "":
        response[STATUS] = FAILED
        response[STATUS_CODE] = 401
        response[MESSAGE] = 'Please enter username and password'
        response[RESULT] = {}
    else:
        user = authenticate(username=user_name, password=password)
        if user is not None:
            if user.is_active and user.is_staff:
                # login is called
                if requested_data.get('otp'):
                    try:
                        otp_details = UserOtp.objects.get(
                            user_id=user.pk)
                    except UserOtp.DoesNotExist:
                        otp_details = None
                    if otp_details is not None and otp_details.otp == requested_data.get('otp') and  timezone.now() - otp_details.create_at < timedelta(minutes=15):
                        del requested_data['otp']
                    else:
                        response[STATUS] = FAILED
                        response[STATUS_CODE] = 200
                        response[MESSAGE] = 'Invalid Otp'
                        response[RESULT] = {}
                        response = json.dumps(response)
                        return HttpResponse(response, content_type="application/json")
                else:
                    random_otp = CommonUtility().random_with_n_digits(6)
                    try:
                        otp_details = UserOtp.objects.get(
                            user_id=user.pk)
                    except UserOtp.DoesNotExist:
                        otp_details = None
                    if otp_details is not None:
                        otp_update_dict = {}
                        otp_update_dict['otp'] = random_otp
                        otp_update_dict['is_expired'] = 0
                        otp_update_dict['create_at'] = datetime.now()
                        otp_update = UserOtp.objects.filter(user_id=user.pk).update(**otp_update_dict)
                    else: 
                        userotp = UserOtp()
                        userotp.user_id = user.pk
                        userotp.otp = random_otp
                        userotp.save()
                    response[STATUS] = SUCCESS
                    response[STATUS_CODE] = 200
                    response[MESSAGE] = 'Check your Mobile for the OTP'
                    response[RESULT] = {}
                    response = json.dumps(response)
                    return HttpResponse(response, content_type="application/json")
                emp_login_dict = {}
                del requested_data['username']
                del requested_data['password']
                try:
                    emp_details = EmployeeMaster.objects.get(
                        user_id=user.pk)
                except EmployeeMaster.DoesNotExist:
                    emp_details = False
                if emp_details:
                    emp_login_dict["employee_id"] = emp_details.id
                for key, value in requested_data.items():
                    emp_login_dict[key] = value
                try:
                    with transaction.atomic():
                        login(request, user)
                        login_details = EmployeeLoginHistory(
                            **emp_login_dict)
                        login_details.save()
                        response[STATUS] = SUCCESS
                        response[STATUS_CODE] = 200
                        response[MESSAGE] = 'You are successfully logged in'
                        response[RESULT] = requested_data
                except Exception as exp:
                    response[STATUS] = FAILED
                    response[STATUS_CODE] = 200
                    response[MESSAGE] = str(exp)
                    response[RESULT] = requested_data
            else:
                response[STATUS] = FAILED
                response[STATUS_CODE] = 401
                response[MESSAGE] = 'Your account is disabled'
                response[RESULT] = {}
        else:
            response[STATUS] = FAILED
            response[STATUS_CODE] = 401
            response[MESSAGE] = 'Invalid login credentials'
            response[RESULT] = {}
    response = json.dumps(response)
    return HttpResponse(response, content_type="application/json")


@csrf_exempt
def logout_user(request):
    """
    Logout from current session
    """
    response = {
        STATUS: FAILED,
        STATUS_CODE: 400,
        MESSAGE: "Something went wrong !!",
        RESULT: {}}

    try:
        # logout is called
        logout(request)
        response[STATUS] = SUCCESS
        response[STATUS_CODE] = 200
        response[MESSAGE] = 'You have successfully logged out'
        response[RESULT] = {}
    except Exception:
        pass
    LOGGER.error(response[MESSAGE])
    response = json.dumps(response)
    return HttpResponse(response, content_type="application/json")


@api_view(["GET", "POST"])
@csrf_exempt
@permission_classes([IsAuthenticated])
def user_detail(request):
    """
    Fetching users details
    """
    response = {
        STATUS: FAILED,
        STATUS_CODE: 400,
        MESSAGE: "Something went wrong !!",
        RESULT: {}}
    requested_data = json.loads(request.body)
    resp = UserService().user_detail(requested_data)
    if resp.get("is_success"):
        response[STATUS] = resp.get("is_success")
        response[STATUS_CODE] = resp.get(STATUS_CODE)
        response[MESSAGE] = resp.get(MESSAGE)
        response[RESULT] = resp.get(RESULT)
    LOGGER.error(response[MESSAGE])
    response = json.dumps(response)
    return HttpResponse(response, content_type="application/json")


@api_view(["POST"])
@csrf_exempt
@permission_classes([IsAuthenticated])
def update_user_status(request):
    """
    Take empcode as input and change that empployee's status as active or in-active
    """
    response = {
        STATUS: FAILED,
        STATUS_CODE: 400,
        MESSAGE: "Something went wrong !!",
        RESULT: {}}
    requested_data = json.loads(request.body)
    resp = UserService().user_action(requested_data)
    if resp.get("is_success"):
        response[STATUS] = resp.get("is_success")
        response[STATUS_CODE] = resp.get(STATUS_CODE)
        response[MESSAGE] = resp.get(MESSAGE)
        response[RESULT] = resp.get(RESULT)
    response = json.dumps(response)
    return HttpResponse(response, content_type="application/json")



@csrf_exempt
@permission_classes([IsAuthenticated])
def update_profile(request):
    """
    Take inputs to be updated and send result with status code
    """
    response = {
        STATUS: FAILED,
        STATUS_CODE: 400,
        MESSAGE: "Something went wrong !!",
        RESULT: {}}
    if request.POST or request.method == "POST":
        requested_data = json.loads(request.body)
        resp = UserService().update_profile(requested_data)
        if resp.get("is_success"):
            response[STATUS] = resp.get("is_success")
            response[STATUS_CODE] = resp.get(STATUS_CODE)
            response[MESSAGE] = resp.get(MESSAGE)
            response[RESULT] = resp.get(RESULT)
            response = json.dumps(response)
    return HttpResponse(response, content_type="application/json")
    

@api_view(["POST"])
@csrf_exempt
@permission_classes([IsAuthenticated])
def change_password(request):
    """
    Change password for user
    """
    response = {
        STATUS: FAILED,
        STATUS_CODE: 400,
        MESSAGE: "Something went wrong !!",
        RESULT: {}}
    requested_data = json.loads(request.body)
    resp = UserService().update_password(requested_data)
    if resp.get("is_success"):
        response[STATUS] = resp.get("is_success")
        response[STATUS_CODE] = resp.get(STATUS_CODE)
        response[MESSAGE] = resp.get(MESSAGE)
        response[RESULT] = resp.get(RESULT)

    response = json.dumps(response)
    return HttpResponse(response, content_type="application/json")

