from django.conf.urls import patterns, include, url
from django.contrib import admin
from SecureWitness import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'mysite.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),
    url(r'^home/$', 'logOn.views.login'),
    url(r'^accounts/auth/$', 'logOn.views.auth_view'),
    url(r'^accounts/logout/$', 'logOn.views.logout'),
    url(r'^accounts/loggedin/$', 'logOn.views.loggedin'),
    url(r'^accounts/invalid/$', 'logOn.views.invalid_login'),
    url(r'^accounts/register/$', 'logOn.views.register_user'),
    url(r'^accounts/register_success/$', 'logOn.views.register_success'),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^SecureWitness/', include('SecureWitness.urls')),
    (r'^accounts/login/$', 'django.contrib.auth.views.login'),
) + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

