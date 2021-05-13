# -*- coding: utf-8 -*-
__author__ = "Anil Kumar  Gupta"
__copyright__ = "Copyright (©) 2017. ORDC. All rights reserved."
__credits__ = ["ORDC"]

# Django related dependencies
from django.conf.urls import url

# Project Related dependencies
from referral.views import web_views as views
#from .service.app_service import app_auth, app_location_detail



web_urls = [ 
    url(r'^share/',views.referrals,name="referrals"),
    
    
]
## Main URL
# urlpatterns = web_urls + app_urls
urlpatterns = web_urls
