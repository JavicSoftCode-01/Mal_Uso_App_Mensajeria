from django.urls import path
from . import views, auth_views

urlpatterns = [
    path('', views.inbox, name='inbox'),
    path('login/', auth_views.login_view, name='login'),
    path('logout/', auth_views.logout_view, name='logout'),
    path('send/', views.send_message, name='send_message'),
    path('chat/<int:user_id>/', views.chat_view, name='chat'),
]