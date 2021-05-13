# -*- coding: utf-8 -*-
__author__ = "Anil Kumar Gupta"
__copyright__ = "Copyright (©) 2018. ordc-warehouse-solution. All rights reserved."
__credits__ = ["ORDC"]

# Django related dependencies
from django.urls import resolve
from django.template import Library
register = Library()


@register.simple_tag
def nav_active(request, url):
    """
    In template: {% nav_active request "url_name_here" %}
    """
    url_name = resolve(request.path).url_name
    url = url.split(" ")
    if url_name in url:
        print("url_name>>>>", url_name)
        return "active"
    return ""
