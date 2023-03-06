from __future__ import annotations

from django.urls import path

from . import views

urlpatterns = [
    path('scan/', views.scan, name='scan'),
    path('get_scan', views.get_scan_data, name='get_scan'),
]
