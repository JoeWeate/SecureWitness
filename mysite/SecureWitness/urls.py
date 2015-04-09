from django.conf.urls import patterns, url

from SecureWitness import views

urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
    url(r'^register/$', views.register, name='register'),
    url(r'^accounts/login/$', 'django.contrib.auth.views.login'),
    url(r'^logout/$', 'django.contrib.auth.views.logout', {'next_page': 'index'}),
    url(r'^(?P<report_id>\d+)/$', views.detail, name='detail'),
    url(r'^create/$', views.create, name='create'),
    url(r'^success/$', views.success, name='success'),
    url(r'^list/$', views.list, name='list'),
    url(r'^groupCreate/$', views.groupCreate, name='groupCreate'),
    url(r'^groupSuccess/$', views.groupSuccess, name='groupSuccess'),
    url(r'^groupList/$', views.groupList, name='groupList'),
    url(r'^groupView/(?P<group_id>\d+)/$', views.groupView, name='groupView'),
    url(r'^addAdmin/$', views.addAdmin, name='addAdmin'),
)