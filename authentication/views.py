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
from django.db.models import Q

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

        messages.add_message(request, messages.SUCCESS, 'Account created successfully! Please check your inbox for the activation link. Please check your spam folder if you do not see it in your inbox and wait a few minutes before trying again.')

        return redirect('login')
    
class LoginView(View):
    def get(self, request):
        return render(request, 'auth/login.html')
    
    def post(self, request):
        context = {
            'data': request.POST,
            'has_error': False
        }
        
        username_or_email = request.POST.get('username_or_email')
        password = request.POST.get('password')

        if username_or_email == '':
            messages.add_message(request, messages.ERROR, 'Email or Username field is required!')
            context['has_error'] = True

        # Query the user based on email or username
        user = User.objects.filter(Q(username=username_or_email) | Q(email=username_or_email)).first()

        if user is not None and user.check_password(password):
            login(request, user)
            return redirect('dashboard')
        else:
            if not context['has_error']:
                messages.add_message(request, messages.ERROR, 'Bad Credentials')
                context['has_error'] = True
        
        if context['has_error']:
            return render(request, 'auth/login.html', status=401, context=context)

    

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
    
class DashboardView(View):
    def get(self, request):
        return render(request, 'dashboard.html')
    
class LogoutView(View):
    def post(self, request):
        logout(request)
        messages.add_message(request, messages.SUCCESS,'Logged out successfully!')
        return redirect('login')

class ProfileView(View):
    def get(self, request):
        return render(request, 'profile.html')
    
class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'auth/request-reset-email.html')
    
    def post(self, request):
        email = request.POST.get("email")

        if not validate_email(email):
            messages.error(request, 'Please enter a valid email!')
            return render(request, 'auth/request-reset-email.html')
        
        user = User.objects.filter(email=email)

        if user.exists():
            current_site = get_current_site(request)
            email_subject = 'Reset Your Password'
            message = render_to_string(
                'auth/reset-user-password.html',
                {
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                    'token': PasswordResetTokenGenerator().make_token(user[0])
                }
            )
            email_message = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [email]
            )

            email_message.send()
        
        # send a generic message anyways to provide no information about users in database
        messages.success(request, 'We have sent you an email with instructions on how to reset your password. '
                          'Please check your spam folder if you do not see it in your inbox and wait a few minutes before trying again.')

        return render(request, 'auth/request-reset-email.html')

class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))

            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.info(
                    request, 'Invalid link! Please request a new one.')
                return render(request, 'auth/request-reset-email.html')

        except DjangoUnicodeDecodeError as identifier:
            messages.success(
                request, 'Invalid link')
            return render(request, 'auth/request-reset-email.html')

        return render(request, 'auth/set-new-password.html', context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token,
            'has_error': False
        }

        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if len(password) < 6:
            messages.add_message(request, messages.ERROR,
                                 'Password must contain atleast 8 characters!')
            context['has_error'] = True
        if password != password2:
            messages.add_message(request, messages.ERROR,
                                 'Passwords do not match!')
            context['has_error'] = True

        if context['has_error'] == True:
            return render(request, 'auth/set-new-password.html', context)

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))

            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()

            messages.success(
                request, 'Password reset success, you can login with your new password!')

            return redirect('login')

        except DjangoUnicodeDecodeError as identifier:
            messages.error(request, 'Something went wrong')
            return render(request, 'auth/set-new-password.html', context)

        return render(request, 'auth/set-new-password.html', context)