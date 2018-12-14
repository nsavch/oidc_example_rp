from django.conf.urls import url

from . import views

app_name = 'authmachine'


urlpatterns = [
    url(r'^callback/$', views.sso_callback, name='sso-callback'),
    url(r'^login/$', views.login, name='sso-login'),
    url(r'^logout/$', views.logout, name='sso-logout'),
]