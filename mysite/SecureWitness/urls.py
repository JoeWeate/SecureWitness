from django.conf.urls import patterns, url

from SecureWitness import views

urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
    url(r'^register/$', views.register, name='register'),
    url(r'^accounts/login/$', 'django.contrib.auth.views.login'),
    url(r'^logout/$', 'django.contrib.auth.views.logout', {'next_page': 'index'}),
    url(r'^(?P<report_id>\d+)/$', views.detail, name='detail'),
    url(r'^create/$', views.create, name='create'),
    url(r'^createSuccess/$', views.createSuccess, name='createSuccess'),
    url(r'^success/$', views.success, name='success'),
    url(r'^list/$', views.list, name='list'),
    url(r'^delete/(?P<report_id>\d+)/$', views.delete, name='delete'),
)