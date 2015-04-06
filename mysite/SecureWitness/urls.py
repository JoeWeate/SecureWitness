from django.conf.urls import patterns, url
from django.contrib.auth.views import login, logout

from SecureWitness import views

urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
    url(r'^(?P<report_id>\d+)/$', views.detail, name='detail'),
    url(r'^login/$', 'django.contrib.auth.views.login'),
    url(r'^logout/$', 'django.contrib.auth.views.logout', {'next_page': '/SecureWitness/'}),
    url(r'^create_report/$', views.create_report, name = 'create_report'),
    url(r'^edit_report/$', views.edit_report, name = 'edit_report'),
)