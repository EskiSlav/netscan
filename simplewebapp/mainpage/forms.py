from __future__ import annotations

from django import forms


class LoginForm(forms.Form):
    username = forms.CharField(max_length=64, label='Username')
    password = forms.CharField(
        label='Password', max_length=128, widget=forms.PasswordInput,
    )
