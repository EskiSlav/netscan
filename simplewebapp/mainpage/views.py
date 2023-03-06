from __future__ import annotations

import socket

from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth import logout
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.shortcuts import render

from .forms import LoginForm


def index(request):
    return redirect(f'http://localhost:8081/login')


def login_view(request):
    message = ''
    status = 200
    if request.user.is_authenticated:
        return HttpResponseRedirect('/cabinet/')

    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = LoginForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return HttpResponseRedirect('/cabinet/')
            else:
                message = 'Invalid login or password'
                status = 403

    form = LoginForm()
    return render(request, 'login.html', {'form': form, 'message': message}, status=status)


def logout_view(request):
    logout(request)
    return HttpResponseRedirect('/login/')


def mainpage(request):
    return render(request, 'index.html')
