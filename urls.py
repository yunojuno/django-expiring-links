# -*- coding: utf-8 -*-
from django.conf.urls import url, include
from django.contrib import admin  # , staticfiles

admin.autodiscover()

urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
    url(r'^testing/', include('test_app.urls', namespace="testing")),
]
