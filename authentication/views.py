from django.shortcuts import render
from django.views.generic import View

# Create your views here.

class RegistrationView(View):
    def get(self, request):
        return render(request, 'auth/register.html')

    def post(self, request):
        data = request.POST
        print(data)
        return render(request, 'auth/register.html', {'data':data})

