from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from .utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth import authenticate, login, logout

from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Create your views here.

class RegistrationView(View):
    def get(self, request):
        return render(request, 'auth/register.html')

    def post(self, request):

        context = {
            'data': request.POST,
            'has_error': False
        }

        email = request.POST.get('email')
        username = request.POST.get('username')
        full_name = request.POST.get('name')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')

        if len(password) < 8:
            messages.add_message(request, messages.ERROR, 'Your password must contain atleast 8 characters.')
            context['has_error'] = True

        if password != password2:
            messages.add_message(request, messages.ERROR, 'Your password does not match with the original one.')
            context['has_error'] = True

        if not validate_email(email):
            messages.add_message(request, messages.ERROR, 'Please provide a valid email!')
            context['has_error'] = True

        if User.objects.filter(email = email).exists():
            messages.add_message(request, messages.ERROR, 'Email is already taken! Please use a different email.')
            context['has_error'] = True

        if User.objects.filter(username = username).exists():
            messages.add_message(request, messages.ERROR, 'Username is already taken! Please use a different username.')
            context['has_error'] = True

        if context['has_error']:
            return render(request, 'auth/register.html', context, status=400)

        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name = full_name
        user.last_name = full_name
        user.is_active = False

        user.save()

        current_site = get_current_site(request)
        email_subject = 'Activate Your Account'
        message = render_to_string(
            'auth/activate.html',
            {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': generate_token.make_token(user)
            }
        )
        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email]
        )

        email_message.send()

        messages.add_message(request, messages.SUCCESS, 'Account created successfully!')

        return redirect('login')
    
class LoginView(View):
    def get(self, request):
        return render(request, 'auth/login.html')
    

class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user = None
        
        if user is not None and generate_token.check_token(user, token):
            user.is_active=True
            user.save()
            messages.add_message(request, messages.SUCCESS, 'Account Activated Successfully!')
            return redirect('login')
        return render(request, 'auth/activate_failed.html', status=401)