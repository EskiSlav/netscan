from __future__ import annotations

from django.urls import path
from django.urls import re_path

from . import views

urlpatterns = [
    path('', views.cabinet, name='cabinet'),
]
