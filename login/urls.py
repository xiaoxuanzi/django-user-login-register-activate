from django.urls import path

from . import views
app_name = 'login'

urlpatterns = [
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('activate/', views.ActivateView.as_view(), name='activate'),
    path('register/', views.RegisterView.as_view(), name='register'),
]