# -*- coding: utf-8 -*-
__author__ = "Anil Kumar  Gupta"
__copyright__ = "Copyright (©) 2017. ORDC. All rights reserved."
__credits__ = ["ORDC"]

# Django related dependencies
from django.conf.urls import url

# Project Related dependencies
from authentication.views import web_views as views
#from .service.app_service import app_auth, app_location_detail



web_urls = [ 
    url(r'^user-registration$', views.user_registration, name="user-registration"),
    url(r'^login$' , views.login_user,name="login"),
    url(r'^logout$' , views.logout_user,name="logout"),
    url(r'^update-profile/$',views.update_profile,name="update-profile"),
    url(r'^otp-varification/$',views.otp_varification,name="otp_varification"),
    url(r'^reset-password$',views.change_password,name="change-password"),
    url(r'^upload-profile$',views.upload_profile,name="upload-profile"),
    #url(r'^forgot-password$',views.upload_profile,name="upload-profile"),
    url(r'^forgot-password',views.ResetPasswordRequestView.as_view(), name="reset_password"),
    url(r'^reset_password_confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$',
                               views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
                           
]
## Main URL
# urlpatterns = web_urls + app_urls
urlpatterns = web_urls
