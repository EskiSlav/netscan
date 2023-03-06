from __future__ import annotations

from django import forms

CHOICES = [('1', 'SYN'), ('2', 'TCP'), ('3', 'UDP')]


class ScanForm(forms.Form):
    network = forms.CharField(max_length=18, initial='172.20.0.0/29')
    host = forms.CharField(max_length=18)
    port = forms.CharField(initial=8081)
    scan_type = forms.ChoiceField(
        widget=forms.RadioSelect, choices=CHOICES, initial='1',
    )
