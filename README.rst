===================================
django-user-login-register-activate
===================================

django-user-login-register-activate is a django app to make user login and registration


Quick start
-----------
1. To install from PyPi::

	pip install django-user-login-register-activate
	
2. Add "login" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'login',
    ]
	
3. Add Email setting like this::

	EMAIL_HOST = "smtp.163.com"
	EMAIL_PORT = 25
	EMAIL_HOST_USER = "your_email_name@163.com"
	EMAIL_HOST_PASSWORD = "your_email_host_password"
	
4. Include the login URLconf in your project urls.py like this::

	from django.contrib import admin
	from django.urls import path, include

	urlpatterns = [
		...
		path('accounts/', include('login.urls')),
	]
	
5. Your can use this project like this::

	from django.contrib.auth.decorators import login_required
	
	@login_required
	def index(request):
		return HttpResponse("Hello World.")
		