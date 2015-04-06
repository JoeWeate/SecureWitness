from django.conf.urls import patterns, include, url
from django.contrib import admin
from SecureWitness import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'mysite.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^admin/', include(admin.site.urls)),
    url(r'^SecureWitness/', include('SecureWitness.urls')),
    (r'^accounts/login/$', 'django.contrib.auth.views.login'),
) + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

