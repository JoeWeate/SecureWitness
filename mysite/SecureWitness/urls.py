from django.conf.urls import patterns, url
from django.contrib.auth.views import login, logout

from SecureWitness import views

urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
    url(r'^(?P<report_id>\d+)/$', views.detail, name='detail'),
    url(r'^login/$', 'django.contrib.auth.views.login'),
    url(r'^logout/$', 'django.contrib.auth.views.logout'),
    
)