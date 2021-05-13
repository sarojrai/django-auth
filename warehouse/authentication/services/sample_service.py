#Python Related dependencies
from random import randint
# Django related dependencies
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _
from django.db import IntegrityError
# Project Related dependencies
from ..models import EmployeeMaster

class SampleService:

    def sample_method(self, requested_data):
        """
        DOCString
        """
        resp = {}
        ## TODO 
        resp["is_success"] = True
        resp["msg"] = "Sample API called"
        resp["result"] = requested_data
        return resp

    def get_user_code(self):
        code = str(uuid.uuid3())[:66]
        return code

    

