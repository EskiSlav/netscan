from __future__ import annotations

import json
import os
from urllib.parse import unquote

import requests
from django.http import HttpResponseBadRequest
from django.http import HttpResponseRedirect
from django.http import JsonResponse
from django.shortcuts import render

from .forms import ScanForm


def is_inside_container():
    if os.path.exists('/.dockerenv'):
        return 1
    return 0


def cabinet(request):
    if not request.user.is_authenticated:
        return HttpResponseRedirect('/login/')

    form = ScanForm()
    return render(request, 'cabinet.html', context={'form': form})
