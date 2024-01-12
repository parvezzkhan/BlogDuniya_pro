from django.contrib import admin
from django.urls import path,include
from .views import UserRegisterView,UserEditView,PasswordChangeView,ShowProfilePageView,EditProfilePageView,CreateProfilePageView,VerifyOTPView,UserLoginView
from django.contrib.auth import views as auth_views
from . import views 
urlpatterns = [
    
    path('register/', UserRegisterView.as_view(), name='register'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('edit_profile/', UserEditView.as_view(), name='edit_profile'),
     path('login/', UserLoginView.as_view(), name='login'),
    # path('password/', auth_views.PasswordChangeView.as_view(template_name='registration/change-password.html')),
    path('password/', PasswordChangeView.as_view(template_name='registration/change-password.html')),
    path('password_success/', views.password_success , name="password_success"),
    path('<int:pk>/profile/',ShowProfilePageView.as_view(),name='show_profile_page'),
    path('<int:pk>/edit_profile_page/',EditProfilePageView.as_view(),name='edit_profile_page'),
    path('create_profile_page/',CreateProfilePageView.as_view(),name='create_profile_page'),
    
    
]
