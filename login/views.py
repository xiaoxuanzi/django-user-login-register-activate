from django.views.generic.base import View
from django.contrib.auth.models import User
from django.shortcuts import redirect
from django.shortcuts import render, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMultiAlternatives
from .tokens import account_activation_token

from django.contrib.auth import authenticate, login, logout
from django.conf import settings

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class LoginView(View):
    def get(self, request, *args, **kwargs):
        is_login = request.session.get('is_login')
        if is_login:
            return HttpResponseRedirect('/')
        else:
            return render(request, 'login/login.html')

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        try:

            input_email = request.POST.get('inputEmail')
            username = input_email.split('@')[0]
            password = request.POST.get('inputPassword')
            user = authenticate(username=username, password=password)
            if user is None:
                raise Exception("Authenticate failed: invalid Email or Password")

        except Exception as e:
            logger.info(repr(e))
            err_msg = repr(e)
            return render(request, 'login/login.html', locals())

        login(request, user)
        return HttpResponseRedirect('/')

class LogoutView(View):
    def get(self, request, *args, **kwargs):
        logout(request)
        return redirect("/")

class RegisterView(View):
    def get(self, request, *args, **kwargs):
        is_login = request.session.get('is_login')
        if is_login:
            return HttpResponseRedirect('/')
        else:
            return render(request, 'login/register.html')

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        try:
            user_id = 0
            password1 = request.POST.get('psw1')
            password2 = request.POST.get('psw2')

            if password1 != password2:
                err_msg = "The password did not match the re-typed password"
                return render(request, 'login/register.html', locals())

            input_email = request.POST.get('inputEmail')
            if User.objects.filter(email=input_email).exists():
                raise Exception("Email Already in Use")

            username = input_email.split('@')[0]
            user = User()
            user.email = input_email
            user.username = username
            user.set_password(password2)
            user.is_active = False
            user.save()
            user_id = user.id

            current_site = get_current_site(request)
            mail_subject = 'Activate your account'

            text_content = '''If you see this message,
                             it means that your email server does not provide HTML link function,
                             please contact the administrator
                             '''
            html_content = '''
                        Please click on the link to confirm your registration,
                        http://{}/accounts/activate?uidb64={}&token={}
            '''.format(current_site.domain,
                       str(urlsafe_base64_encode(force_bytes(user.pk)), encoding='utf-8'),
                       account_activation_token.make_token(user))

            msg = EmailMultiAlternatives(mail_subject, text_content, settings.EMAIL_HOST_USER, [input_email])
            msg.attach_alternative(html_content, "text/html")
            msg.send()

        except Exception as e:
            # delete user when register fail
            if user_id != 0:
                u = User.objects.get(id=user.id)
                u.delete()

            logger.info(repr(e))
            err_msg = repr(e)
            return render(request, 'login/register.html', locals())

        msg = 'Please check the email, click the activation link and login'
        return render(request, 'login/notice_template.html', locals())

class ActivateView(View):
    def get(self, request, *args, **kwargs):
        try:
            uidb64 = request.GET.get('uidb64')
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        token = request.GET.get('token')
        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            return render(request, 'login/login.html')
        else:
            msg = 'Activation link is invalid!'
            return render(request, 'login/notice_template.html', locals())
