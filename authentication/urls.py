from django.urls import path
from . import views
from django.contrib.auth.decorators import login_required

urlpatterns = [
    path('auth/register/', views.RegistrationView.as_view(), name='register'),
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    path('', login_required(views.DashboardView.as_view()), name='dashboard'),
    path('profile/', login_required(views.ProfileView.as_view()), name='profile'), 
    path('auth/activate/<uidb64>/<token>', views.ActivateAccountView.as_view(), name='activate'),
    path('auth/set-new-password/<uidb64>/<token>', views.SetNewPasswordView.as_view(), name='set-new-password'),
    path('auth/request-reset-email/', views.RequestResetEmailView.as_view(), name='request-reset-email')
]
