# -*- coding: utf-8 -*-
__author__ = "Anil Kumar  Gupta"
__copyright__ = "Copyright (©) 2017. ORDC. All rights reserved."
__credits__ = ["ORDC"]
#  Python module and packages

from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def referrals(request):
    """ Sharing link using social referrals """
    ref_url = "http://127.0.0.1:8000/"
    context = {"title1": "referrals", "title2": "share",
               "ref_url": ref_url,
               "company": "ORDC",
               "amount": "100"
               }
    return render(request, 'referrals.html', context)
