# -*- coding: utf-8 -*-
__author__ = "Anil Kumar Gupta"
__copyright__ = "Copyright (©) 2017. ORDC. All rights reserved."
__credits__ = ["ORDC"]

class Constant:
    """
    Constant is class used to store all string literals
    """ 
    ## HTML PAGE Lables
    PAGE_TITLE1 = "Door"
    PAGE_TITLE2 = "Delvr"


    
    # Single Characters
    FILE_SEPARATOR = '/'
    ENV_SEPARATOR = '://'
    FILE_EXTENSION_SEPARATOR = '.'
    PROPERTIES_FILE_SEPERATOR = '=' 
    UNDERSCORE = '_'
    COLON = ':'
    ENVIRONMENT = 'gs'
    BLANK = ''
 
    # All temp file path
    LOCAL_LOCATION_OF_LOG = '/tmp/log_files/'
    LOCAL_LOCATION_OF_DOWNLOAD = '/tmp/lastmile'
    LOCAL_LOCATION_OF_URL_FILE = '/tmp/url.txt'
    LOCAL_LOCATION_OF_PLATFORM_FILE = '/tmp/platform.ini'

    # Authentication 
    USERNAME_ALREADY_EXIST = "USERNAME_ALREADY_EXIST"
    USER_CREATED = "USER_CREATED"
    INCORRECT_USERNAME_OR_PASSWORD = "INCORRECT_USERNAME_OR_PASSWORD"
    ACCESSED = "ACCESSED"
    LOGGED_IN_AGAIN = "LOGGED_IN_AGAIN"    
    LOGOUT_FIRST = "LOGOUT_FIRST"
    LOGOUT = "LOGOUT"
    
    # Request & Response Key
    # Request & Response  parameter
    # Status code for Validation Erros
    IMPROPER_REQUEST = 'IMPROPER_REQUEST'
    IMPROPER_RESPONSE = 'IMPROPER_RESPONSE'

    # Messages for Validation Erros
    IMPROPER_REQUEST_MESSAGE = 'Improper request'
    IMPROPER_RESPONSE_MESSAGE = 'Improper response'

    # Messages for Service Erros
    SERVICE_ERROR_MESSAGE = 'Service error'
    FILE_ERROR = '%s : Invalid File Path or File does not exist'
    JSON_FORMAT_ERROR= '%s : not a json file or incorrect json'
    #Log message used in utils
    UNABLE_TO_DOWNLOAD_LOG ='Unable to download given file'
    BUCKET_NOT_FOUND_LOG = 'Sorry, given bucket does not exist.'
    B ='Blob %s downloaded to %s.'
    # Constants used in MASTERs)
    # ++++++++++++++START++++++++++++++++++++
    ORG_CODE = "ORD"
    CODE_FOR = {"CUST":1000,"SPLR":1000,"MFR":1000,\
                "ITEM":7000000,"TRANS":1000, "EMP":100\
               }
    CUSTOMER = "CUSTOMER" 
    # ++++++++++++++END++++++++++++++++++++++
   

    # ++++++++++++++END of Process logic used Constants ++++++++++++++++++++
