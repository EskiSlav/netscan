from __future__ import annotations

import json
import logging

from django.http import HttpRequest
from django.http import JsonResponse
from scanner.scanner import Scanner
# from django.shortcuts import render
# Create your views here.
logger = logging.getLogger(__name__)


def scan(request: HttpRequest):
    logger.debug(request)
    body = json.loads(request.body)

    network = body.get('network')
    host = body.get('host')
    port = body.get('port')
    scan_type = body.get('scan_type')

    response_data = {
        'dnetwork': network,
        'dhost': host,
        'dport': port,
        'scan_type': scan_type,
    }

    scan_id = Scanner().scan(**response_data)

    return JsonResponse({
        'ok': True,
        'status': 200,
        'scan_id': scan_id,
    })


def get_scan_data(request: HttpRequest):

    scan_id = request.GET.get('scan_id')

    scan = Scanner.get_scan(scan_id)

    return JsonResponse({
        'ok': True,
        'status': 200,
        'data': scan,
    })
