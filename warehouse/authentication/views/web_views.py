# -*- coding: utf-8 -*-
__author__ = "Anil Kumar  Gupta"
__copyright__ = "Copyright (©) 2017. ORDC. All rights reserved."
__credits__ = ["ORDC"]
#  Python module and packages
import json
import re
import logging
from datetime import datetime, timedelta
LOGGER = logging.getLogger(__name__)

# # Django module and packages

from django.http import JsonResponse
from django.utils import timezone
from django.shortcuts import render
from django.contrib import messages
from django.db import transaction
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth.decorators import login_required

# # Project related module and packages
from authentication.utils.constant import Constant
from authentication.utils.common_utility import CommonUtility
from authentication.forms import  PhotoForm, PasswordResetRequestForm, SetPasswordForm
from authentication.models import EmployeeMaster, EmployeeLoginHistory, UserOtp, Photo, City, State, Country
from authentication.services.user_service import UserService
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.db.models.query_utils import Q
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template import loader
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from warehouse.settings import DEFAULT_FROM_EMAIL
from django.views.generic import *
from django.contrib.auth.models import User

# Global Variable
STATUS = "status"
STATUS_CODE = "status_code"
MESSAGE = "message"
RESULT = "result"
SUCCESS = "Success"
FAILED = "Failed"



def user_registration(request):
    """
    Take user information as input for user registration and return result with status code
    """
    if request.method == "POST":
        requested_data = json.dumps(request.POST)
        requested_data = json.loads(requested_data)
        del requested_data['csrfmiddlewaretoken']
        resp = UserService().user_register(requested_data)
        if resp.get("is_success") == 'Success':
            messages.success(request, resp.get(MESSAGE))
            return HttpResponseRedirect("/")
        context = {
            "title1": "Door",
            "title2": "Delvr",
            "form_error": resp.get(MESSAGE),
            "status_code": resp.get(STATUS_CODE),
            "data": resp.get(RESULT)}
        return render(request, 'authentication/registration.html', context)
    else:
        context = {
            "title1": Constant.PAGE_TITLE1,
            "title2": Constant.PAGE_TITLE2}
        return render(request, 'authentication/registration.html', context)


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
    if request.POST or request.method == "POST":
        requested_data = json.dumps(request.POST)
        requested_data = json.loads(requested_data)
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
                    request.session['user_name'] = user_name
                    request.session['auth'] = password
                    if requested_data.get('otp'):
                        try:
                            otp_details = UserOtp.objects.get(
                                user_id=user.pk)
                        except UserOtp.DoesNotExist:
                            otp_details = None

                        if otp_details is not None and otp_details.otp == requested_data.get(
                                'otp') and timezone.now() - otp_details.create_at < timedelta(minutes=15):
                            del requested_data['otp']

                        else:
                            messages.error(request, 'Invalid Otp !')
                            return HttpResponseRedirect(
                                "/auth/web/otp-varification")
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
                            otp_update = UserOtp.objects.filter(
                                user_id=user.pk).update(**otp_update_dict)
                        else:
                            userotp = UserOtp()
                            userotp.user_id = user.pk
                            userotp.otp = random_otp
                            userotp.save()
                        return HttpResponseRedirect(
                            "/auth/web/otp-varification")
                    
                    emp_login_dict = {}
                    del requested_data['username']
                    del requested_data['web_access']
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
                            # add into employee login history
                            # print("emp_login_dict", emp_login_dict)
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

    if response[STATUS] == "Success":
        request.session['employee_code'] = emp_details.employee_code
        return HttpResponseRedirect(
            "/auth/web/update-profile?employee_code=" +
            emp_details.employee_code)
    elif response[STATUS] == "Failed":
        messages.error(request, 'Invalid login credentials !')
        return HttpResponseRedirect("/")
    else:
        response = json.dumps(response)
        return HttpResponse(response, content_type="application/json")

def logout_user(request):
    """
    Logout from current session
    """
    try:
        logout(request)
        messages.success(request, 'You have successfully logged out')
        LOGGER.error('You have successfully logged out')
        return HttpResponseRedirect("/")
    except Exception:
        pass


def get_html_input_dict(query_dict, param):
    """ grouping post value using name"""
    dictionary = {}
    regex = re.compile(r'%s\[([\w\d_]+)\]' % param)
    for key, value in query_dict.items():
        match = regex.match(key)
        if match:
            inner_key = match.group(1)
            dictionary[inner_key] = value
    return dictionary


@login_required(login_url='landing_page')
def update_profile(request):
    """
    Take inputs to be updated and send result with status code
    """
    if request.POST or request.method == "POST":
        final_dict = {}
        general_details = get_html_input_dict(request.POST, "general_details")
        parmanent_address = get_html_input_dict(
            request.POST, "parmanent_address")
        communication_address = get_html_input_dict(
            request.POST, "communication_address")
        contact_detail = get_html_input_dict(request.POST, "contact_detail")
        company_detail = get_html_input_dict(request.POST, "company_detail")
        kyc_detail = get_html_input_dict(request.POST, "kyc_detail")

        details_dict = {}
        details_dict["general_details"] = general_details
        details_dict["parmanent_address"] = parmanent_address
        details_dict["communication_address"] = communication_address
        details_dict["contact_detail"] = contact_detail
        details_dict["company_detail"] = company_detail
        details_dict["kyc_detail"] = kyc_detail
        final_dict[request.GET["employee_code"]] = details_dict

        requested_data = json.dumps(final_dict)
        requested_data = json.loads(requested_data)
        resp = UserService().update_profile(requested_data)
        if resp.get("is_success"):
            requested_data_exist = {}
            requested_data_exist['employee_code'] = request.GET['employee_code']
            resp = UserService().user_detail(requested_data_exist)
            city_dict = City.objects.all().order_by('id')
            state_dict = State.objects.all().order_by('id')
            country_dict = Country.objects.all().order_by('id')
            context = {"resp": resp['result'][request.GET['employee_code']],
                       "employee_code": request.GET['employee_code'],
                       "city_dict": city_dict,
                       "state_dict": state_dict,
                       "country_dict": country_dict}
            messages.success(request, resp.get(MESSAGE))
            return render(request, "authentication/profile.html", context)
        else:
            resp = requested_data
            city_dict = City.objects.all().order_by('id')
            state_dict = State.objects.all().order_by('id')
            country_dict = Country.objects.all().order_by('id')
            context = {"resp": resp['result'][request.GET['employee_code']],
                       "employee_code": request.GET['employee_code'],
                       "city_dict": city_dict,
                       "state_dict": state_dict,
                       "country_dict": country_dict}
            messages.error(request, resp.get(MESSAGE))
            return render(request, "authentication/profile.html", context)

    else:
        requested_data = {}
        requested_data['employee_code'] = request.GET['employee_code']
        resp = UserService().user_detail(requested_data)
        city_dict = City.objects.all().order_by('id')
        state_dict = State.objects.all().order_by('id')
        country_dict = Country.objects.all().order_by('id')
        context = {"title":"User Profile", "resp": resp['result'][request.GET['employee_code']],
                   "employee_code": request.GET['employee_code'],
                   "city_dict": city_dict,
                   "state_dict": state_dict,
                   "country_dict": country_dict}
        return render(request, "authentication/profile.html", context)

@login_required(login_url='landing_page')
def change_password(request):
    """
    Change password for user
    """
    if request.POST or request.method == "POST":
        employee_code = request.session['employee_code']
        requested_data = json.dumps(request.POST)
        requested_data = json.loads(requested_data)
        del requested_data['csrfmiddlewaretoken']
        resp = UserService().update_password(requested_data)
        if resp.get("is_success") == 'Success':
            messages.success(request, resp.get(MESSAGE))
            return HttpResponseRedirect(
            "/auth/web/update-profile?employee_code=" +
            employee_code)
        context = {
            "title":"Reset Password",
            "form_error": resp.get(MESSAGE),
            "status_code": resp.get(STATUS_CODE),
            "data": resp.get(RESULT)}
        return render(request, 'authentication/change-password.html', context)
        
    else:
        context = {"title":"Reset Password"}
        return render(request, "authentication/change-password.html", context)


@csrf_exempt
def otp_varification(request):
    """ Otp varifaction"""
    user_name = request.session['user_name']
    password = request.session['auth']
    login_url = "/auth/web/login"
    context = {"title1": "Door", "title2": "Delvr",
               "login_url": login_url,
               "user_name": user_name,
               "password": password

               }
    return render(request, 'authentication/otp.html', context)

@csrf_exempt
def upload_profile(request):
    """
    image upload for locale storage
    and represent as json .
    """
    model = Photo.objects.get_or_create(
        employee_code=request.POST['employee_code'])
    form = PhotoForm(request.POST, request.FILES, instance=model)
    if form.is_valid():
        photo = form.save()
        data = {
            'is_valid': True,
            'name': photo.file.name,
            'url': photo.file.url}
    else:
        data = {'is_valid': False}
    return JsonResponse(data)

class ResetPasswordRequestView(FormView):
    # code for template is given below the view's code
    # template_name = "account/test_template.html"
    template_name = "authentication/forgot_password.html"
    success_url = '/'
    form_class = PasswordResetRequestForm

    @staticmethod
    def validate_email_address(email):

        try:
            validate_email(email)
            return True
        except ValidationError:
            return False

    def reset_password(self, user, request):
        c = {
            'email': user.email,
            'domain': request.META['HTTP_HOST'],
            'site_name': 'your site',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'user': user,
            'token': default_token_generator.make_token(user),
            'protocol': 'http',
        }
        subject_template_name = 'registration/password_reset_subject.txt'
        # copied from
        # django/contrib/admin/templates/registration/password_reset_subject.txt
        # to templates directory
        email_template_name = 'registration/password_reset_email.html'
        
        # copied from
        # django/contrib/admin/templates/registration/password_reset_email.html
        # to templates directory
        subject = loader.render_to_string(subject_template_name, c)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())
        email = loader.render_to_string(email_template_name, c)
        print(email)
        # send_mail(subject, email, DEFAULT_FROM_EMAIL,
        #           [user.email], fail_silently=False)
        

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        try:
            if form.is_valid():
                data = form.cleaned_data["email_or_username"]
            # uses the method written above
            if self.validate_email_address(data) is True:
                '''
                If the input is an valid email address, then the following code will lookup for users associated with that email address. If found then an email will be sent to the address, else an error message will be printed on the screen.
                '''
                associated_users = User.objects.filter(
                    Q(email=data) | Q(username=data))
                if associated_users.exists():
                    for user in associated_users:
                        self.reset_password(user, request)

                    result = self.form_valid(form)
                    messages.success(
                        request, 'An email has been sent to {0}. Please check its inbox to continue reseting password.'.format(data))
                    return result
                result = self.form_invalid(form)
                messages.error(
                    request, 'No user is associated with this email address')
                return result
            else:
                '''
                If the input is an username, then the following code will lookup for users associated with that user. If found then an email will be sent to the user's address, else an error message will be printed on the screen.
                '''
                associated_users = User.objects.filter(username=data)
                if associated_users.exists():
                    for user in associated_users:
                        self.reset_password(user, request)
                    result = self.form_valid(form)
                    messages.success(
                        request, "Email has been sent to {0}'s email address. Please check its inbox to continue reseting password.".format(data))
                    return result
                result = self.form_invalid(form)
                messages.error(
                    request, 'This username does not exist in the system.')
                return result
            messages.error(request, 'Invalid Input')
        except Exception as e:
            print(e)
        return self.form_invalid(form)

class PasswordResetConfirmView(FormView):
    template_name = "authentication/password_change_form.html"
    
    success_url = '/'
    form_class = SetPasswordForm

    def post(self, request, uidb64=None, token=None, *arg, **kwargs):
        """
        View that checks the hash in a password reset link and presents a
        form for entering a new password.
        """
        UserModel = get_user_model()
        form = self.form_class(request.POST)
        assert uidb64 is not None and token is not None  # checked by URLconf
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            if form.is_valid():
                # Validate Password Policy
                new_password = form.cleaned_data['new_password2']
                is_password_valid = CommonUtility().validate_password_strength(new_password)
                if  is_password_valid == 'success':
                    
                    user.set_password(new_password)
                    user.save()
                    messages.success(request, 'Password has been reset.')
                    return self.form_valid(form)
                else:
                    messages.success(request, is_password_valid)
                    return self.form_valid(form)
                    
                
            else:
                messages.error(
                    request, 'Password reset has not been successful.')
                return self.form_invalid(form)
        else:
            messages.error(
                request, 'The reset password link is no longer valid.')
            return self.form_invalid(form)