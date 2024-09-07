from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User

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
        messages.add_message(request, messages.SUCCESS, 'Account created successfully!')

        return redirect('login')
    
class LoginView(View):
    def get(self, request):
        return render(request, 'auth/login.html')