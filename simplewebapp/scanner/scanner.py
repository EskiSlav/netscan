from __future__ import annotations

import ipaddress
import logging
import os
import urllib.parse
from random import randint
from typing import List

from scapy.all import *

# Initialize the nmap object
logger = logging.getLogger(__name__)

CHOICES = [('1', 'SYN'), ('2', 'TCP'), ('3', 'UDP')]


class Scanner:
    SCAN_TYPES = {
        '1': 'syn',
        '2': 'tcp',
        '3': 'udp',
    }

    def __init__(self) -> None:
        logger.info('Scanner init...')
        try:
            os.mkdir('scans')
        except FileExistsError:
            pass

    @staticmethod
    def get_scan(scan_id: str | int):
        try:
            with open(f'scans/scan_{scan_id}.txt') as f:
                return f.read()
        except FileNotFoundError:
            return 'Scanning ...'

    def scan(self, dnetwork=None, dhost=None, dport=None, scan_type=None, *args, **kwargs):

        dnetwork = urllib.parse.unquote(dnetwork)
        scan_types = {
            'syn': self.syn_scan,
            'tcp': self.tcp_scan,
            'udp': self.udp_scan,
            'icmp': self.icmp_scan,
        }
        scan_type = Scanner.SCAN_TYPES[scan_type]
        scan_func = scan_types.get(scan_type)

        if (dnetwork is None or dnetwork == '') and (dhost is None == ''):
            logger.warning(
                f'No dnetwork or dhost were provided. {dnetwork=} {dhost=}',
            )
            return -1

        if not dnetwork is None and not dhost is None and not dnetwork == '' and not dhost == '':
            logger.warning(
                f'Both dnetwork and dhost were provided. {dnetwork=} {dhost=}',
            )
            return -1

        if scan_func is None:
            logger.warning(
                f'The following scan type is not supported. {scan_type=}',
            )
            return -1

        params = {
            'dnetwork': dnetwork,
            'dhost': dhost,
            'dport': dport,
            'scan_type': scan_type,
            'scan_id': randint(1000, 10000),
        }
        logger.debug(f'{params=}')

        if not dhost is None and not dport is None:
            t = Thread(target=scan_func, kwargs=params)
            t.start()

        elif not dnetwork is None and not dport is None:
            t = Thread(target=scan_func, kwargs=params)
            t.start()

        return params.get('scan_id')

    def syn_scan(self, dnetwork=None, dhost=None, dport=None, scan_type=None, scan_id=None, *args, **kwargs):
        logger.info('SYN scan started...')
        logger.debug(f'{dnetwork=} {dhost=} {dport=} {scan_type=} {scan_id=}')

        if isinstance(dport, list):
            dport = [int(port) for port in dport]
        elif isinstance(dport, str):
            if '-' in dport:
                port_range = dport.split('-')
                dport = list(range(int(port_range[0]), int(port_range[1])))
            else:
                dport = int(dport)

        out = open(f'scans/scan_{scan_id}.txt', 'w')
        out.write('---- SYN Scan started ----\n')
        out.flush()

        def _syn_host_scan(dhost=None, dport=None):
            # Create a SYN packet
            packet = IP(dst=dhost)/TCP(dport=dport, flags='S')
            # Send the packet and receive the response
            logger.debug(f'{packet=}')
            response = sr1(packet, timeout=10, verbose=0)

            # Check if the port is open or closed
            if response:
                logger.debug(f'{response=}')
                logger.debug(f'{response[TCP]=}')
                logger.debug(f'{response[TCP].flags=}')
                if response[TCP].flags == 18:
                    out.write(f'Host: {dhost}: Port {dport} is open\n')
                else:
                    out.write(f'Host: {dhost}: Port {dport} is closed\n')
            else:
                out.write(f'Port {dport} is closed or filtered\n')

            out.flush()

        if dnetwork is not None:
            net = ipaddress.ip_network(dnetwork)
        elif dhost is not None:
            net = [ipaddress.ip_address(dhost)]

        for host in net:
            out.write(f"Scanning Host '{out.flush()}'\n")
            out.flush()
            if isinstance(dport, list):
                for port in dport:
                    _syn_host_scan(host, port)
            else:
                _syn_host_scan(host, dport)

        out.write('-------- FINISHED --------')
        out.close()

    def tcp_scan(self, dnetwork=None, dhost=None, dport=None, scan_type=None, *args, **kwargs):
        logger.debug('tcp_scan started...')

    def udp_scan(self, dnetwork=None, dhost=None, dport=None, scan_type=None, *args, **kwargs):
        logger.debug('udp_scan started...')

    def icmp_scan(self, dnetwork=None, dhost=None, dport=None, scan_type=None, *args, **kwargs):
        logger.debug('icmp_scan started...')

    # def ping_scan(self, network_range):
    #     logger.info("Started ping scan...")
    #     # Perform the scan

    # def ssh_scan(self, network_range):
    #     logger.info("Started ssh scan...")

    # def http_scan(self, network_range):
    #     logger.info("Started http scan...")

    # def https_scan(self, network_range):
    #     logger.info("Started http scan...")

    # def hosts_discovery(self, network_range):
    #     self.ping_scan(network_range)
    #     self.ssh_scan(network_range)
    #     self.http_scan(network_range)
    #     self.https_scan(network_range)


if __name__ == '__main__':
    s = Scanner()
    # for i in range(5400, 5500):
    s.syn_scan('127.0.0.1', 5432)
