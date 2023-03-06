from __future__ import annotations

from django.test import SimpleTestCase
from django.urls import resolve
from django.urls import reverse
from mainpage.views import index
from mainpage.views import login_view
from mainpage.views import logout_view


class TestUrls(SimpleTestCase):

    def test_index_url_is_resolved(self):
        url = resolve(reverse('index'))
        self.assertEqual(url.func, index)

    def test_index_url_is_resolved(self):
        url = resolve(reverse('login'))
        self.assertEqual(url.func, login_view)

    def test_index_url_is_resolved(self):
        url = resolve(reverse('logout'))
        self.assertEqual(url.func, logout_view)
