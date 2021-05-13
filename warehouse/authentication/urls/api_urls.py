# -*- coding: utf-8 -*-
__author__ = "Anil Kumar  Gupta"
__copyright__ = "Copyright (©) 2017. ORDC. All rights reserved."
__credits__ = ["ORDC"]

# Django related dependencies
from django.conf.urls import url

# Project Related dependencies
from authentication.views import api_views as views
#from .service.app_service import app_auth, app_location_detail



web_urls = [ 
    url(r'^user-registration$', views.user_registration, name="user-registration"),
    url(r'^login$' , views.login_user,name="login"),
    url(r'^logout$' , views.logout_user,name="logout"),
    url(r'^get-user-detail/$' , views.user_detail,name="get-user-detail"),
    url(r'^update-user-status/$', views.update_user_status,name="update-user-status"),
    url(r'^update-profile/$',views.update_profile,name="update-profile"),
    url(r'^reset-password$',views.change_password,name="change-password"),
    url(r'^api-token-auth/', views.CustomAuthToken.as_view())
    
]
## Main URL
# urlpatterns = web_urls + app_urls
urlpatterns = web_urls
