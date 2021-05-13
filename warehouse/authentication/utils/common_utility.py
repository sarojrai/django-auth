# -*- coding: utf-8 -*-
__author__ = "Anil Kumar  Gupta"
__copyright__ = "Copyright (©) 2017. ORDC. All rights reserved."
__credits__ = ["ORDC"]


# Python Related Dependencies
import datetime
import uuid
import os
import random
# Django related dependencies
# Project Related dependencies
from authentication.utils.constant import Constant

class CommonUtility:

    def get_datetime_now(self):
        now = datetime.datetime.now()
        return now
  
    def create_folder(self, folder_key):
        """
        create_folder function is used to take the folder key
        @param:
            folder_key = path to create folder with folder name e.g.:/tmp/sample_output/
        """
        # create a output folder if not exist
        if not os.path.exists(folder_key):
            os.makedirs(folder_key)
    
    def get_YYYY_MM_DD(self, date):
        try:
            new_format = datetime.datetime.strptime(str(date), '%d-%m-%Y').strftime('%Y-%m-%d') 
        except:
            new_format = datetime.datetime.now()
        return str(new_format)

    def get_YYYY_MM_DD_from_DD_MM_YYYY(self, date):
        try:
            new_format = datetime.datetime.strptime(str(date), '%d-%m-%Y').strftime('%Y-%m-%d')
        except Exception as e:
            print ("E", str(e))
            new_format = datetime.datetime.now()
        return str(new_format)
   
    def get_age(self, date_from):
        now = datetime.datetime.now()
        age_in_days = (now - date_from).days
        years = 0
        months = 0
        years = int(age_in_days/365)
        rem_days = age_in_days%365
        months = int(rem_days/30)
        days = rem_days%30
        age = "".join([str(years),"Y", str(months), "M",str(days), "D"])
        return age
 
  
    def get_file_extension(self, file_format):
        file_extension = {"CSV":".csv","EXCEL":".xlsx", "XLS":".xls","PDF":".pdf"}
        try:
            ext = file_extension[file_format]
        except Exception as e:
            ## TODO Log
            ext = e
        return ext

    def get_24_hr_date_time(self, from_date, to_date):
        today = datetime.datetime.today()
        buffer_day = datetime.timedelta(5)
        if from_date=="":
            from_date = (today-buffer_day).strftime('%Y-%m-%d')
        if to_date=="":
            to_date = today.strftime('%Y-%m-%d')
        try:
            from_date = self.get_YYYY_MM_DD_from_DD_MM_YYYY(from_date) 
            to_date = self.get_YYYY_MM_DD_from_DD_MM_YYYY(to_date)
        except Exception as e:
            print("Invalid Date Format")
        from_date = str(from_date)+" 00:00:00" 
        to_date = str(to_date)+" 23:59:59"
        return from_date, to_date


    def generate_code(self, code_for, latest_id, org_code=None):
        code_for = str(code_for.rstrip()).upper()
        u_id = str(uuid.uuid4())[-6:].upper()
        code_prefix = Constant.CODE_FOR[code_for]
        if org_code:
            code = int(code_prefix)+int(latest_id)
            code_prefix = str(org_code).upper()
        else:
            code = u_id+str(latest_id)
            code = code[-8:]
            code_prefix = code_for
        try:
            new_code = "{0}{1}".format(code_prefix, code)
            # print (new_code)
        except Exception as e:
            new_code = "{0}{1}".format(code_for, code)
            # print("E..",str(e))
        return str(new_code)

    def random_with_n_digits(self, n):
        """ Genrate n digit random number
        """
        range_start = 10**(n-1)
        range_end = (10**n)-1
        return random.randint(range_start, range_end)

    def validate_password_strength(self, value):
        """Validates that a password is as least 8 characters long and has at least
        1 digit and 1 letter.
        """
        min_length = 8
        min_digit = 1
        min_char = 1

        if len(value) < min_length:
            return 'Password must be at least {0} characters long.'.format(min_length)
            
        # check for digit
        if not any(char.isdigit() for char in value):
            return 'Password must contain at least {0} digit.'.format(min_digit)
            
        # check for letter
        if not any(char.isalpha() for char in value):
            return 'Password must contain at least {0} letter.'.format(min_char)
        else:
            return "success"
    
    
            
