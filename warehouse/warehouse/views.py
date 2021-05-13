from django.shortcuts import render



def landing_page(request):
    """
    landing page of ERP
    """
    login_url = "/auth/web/login"
    context = {"title1":"Door", "title2":"Delvr",
               "login_url":login_url
               }
    return render(request, 'authentication/login.html', context)