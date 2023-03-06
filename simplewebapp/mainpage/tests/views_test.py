from __future__ import annotations

import json
from pydoc import resolve

from django.contrib.auth import get_user_model
from django.test import Client
from django.test import TestCase
from django.urls import reverse


class TestViews(TestCase):

    def setUp(self):
        self.client = Client()
        User = get_user_model()
        User.objects.create_superuser('Hero', 'of@the.com', 'Storm')

    def test_login_system_with_non_existing_user(self):
        url = reverse('login')
        data = {  # Wrong creds
            'username': 'Heros',
            'password': 'Storm',
        }
        response = self.client.post(url, data, follow=True)

        self.assertEqual(response.status_code, 403)
        self.assertTemplateUsed(response, 'login.html')

    def test_login_system_with_existing_user(self):
        url = reverse('login')
        data = {  # Right creds
            'username': 'Hero',
            'password': 'Storm',
        }
        response = self.client.post(url, data, follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'cabinet.html')

    def test_index_redirecting(self):
        response = self.client.get(reverse('index'), follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'login.html')
