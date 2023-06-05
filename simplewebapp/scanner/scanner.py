from __future__ import annotations

import ipaddress
import logging
import os
import urllib.parse
from datetime import datetime

from scapy.all import *
# from typing import List
# from scapy.all import *
# Initialize the nmap object
logger = logging.getLogger(__name__)

CHOICES = [('1', 'SYN'), ('2', 'TCP'), ('3', 'UDP'), ('4', 'ICMP')]


class Scanner:
    SCAN_TYPES = {
        '1': 'syn',
        '2': 'tcp',
        '3': 'udp',
        '4': 'icmp',
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

        if dnetwork is not None and dhost is not None and not dnetwork == '' and not dhost == '':
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
            'scan_id': datetime.now().strftime('%d%m%Y_%H_%M_%S_%f'),
        }
        logger.debug(f'{params=}')

        if dhost is not None and dport is not None:
            t = Thread(target=scan_func, kwargs=params)
            t.start()

        elif dnetwork is not None and dport is not None:
            t = Thread(target=scan_func, kwargs=params)
            t.start()

        return params.get('scan_id')

    def _preprocess_scan_arguments(self, dnetwork=None, dhost=None, dport=None):
        logger.debug('Processing arguments')
        if dnetwork is not None and dnetwork != '':
            net = [str(ip) for ip in ipaddress.ip_network(dnetwork)]
        elif dhost is not None and dhost != '':
            net = [str(ipaddress.ip_address(dhost))]
        logger.debug(f'{net=}')

        if isinstance(dport, list):
            ports = [int(port) for port in dport]
        elif isinstance(dport, str):
            if '-' in dport:
                port_range = dport.split('-')
                ports = list(range(int(port_range[0]), int(port_range[1])))
            else:
                ports = [int(dport)]
        logger.debug(f'{ports=}')

        return net, ports

    def _syn_host_scan(self, dhost=None, dport=None, out=None):
        # Create a SYN packet
        packet = IP(dst=dhost) / TCP(dport=dport, flags='S')
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

    def _tcp_host_scan(self, dhost=None, dport=None, out=None):
        ip = IP(dst=dhost)

        syn_packet = ip / TCP(dport=dport, flags='S')
        logger.debug(f'{syn_packet=}')
        syn_response = sr1(syn_packet, timeout=10, verbose=0)
        logger.debug(f'{syn_response=}')

        if syn_response:
            ack_packet = TCP(
                sport=syn_response.sport, dport=dport,
                flags='A', seq=syn_response.ack, ack=syn_response.seq + 1,
            )
            logger.debug(f'{ack_packet=}')
            send(ip / ack_packet)

        # Check if the port is open or closed
        if syn_response:
            logger.debug(f'{syn_response=}')
            logger.debug(f'{syn_response[TCP]=}')
            logger.debug(f'{syn_response[TCP].flags=}')
            if syn_response[TCP].flags == 18:
                out.write(f'Host: {dhost}: Port {dport} is open\n')
            else:
                out.write(f'Host: {dhost}: Port {dport} is closed\n')
        else:
            out.write(f'Host: {dhost}: Port {dport} is closed or filtered\n')

        out.flush()

    def _udp_host_scan(self, dhost=None, dport=None, out=None):
        packet = IP(dst=dhost) / UDP(dport=dport)
        response = sr1(packet, timeout=2, verbose=0)

        if response is None:
            out.write(f'Host: {dhost}: Port {dport} is open or filtered\n')

        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                out.write(f'Host: {dhost}: Port {dport} is filtered\n')
            else:
                out.write(f'Host: {dhost}: Port {dport} is closed\n')

        elif response.haslayer(UDP):
            out.write(f'Host: {dhost}: Port {dport} is open\n')

        else:
            out.write(f'Host: {dhost}: Port {dport} is closed\n')

        out.flush()

    def _icmp_host_scan(self, dhost=None, out=None):
        packet = IP(dst=dhost) / ICMP()
        # Send the packet and receive the response
        logger.debug(f'{packet=}')
        response = sr1(packet, timeout=1, verbose=0)

        if response is None:
            out.write(f'Host: {dhost} - No response\n')
        elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:
            out.write(f'Host: {dhost} - Host is up\n')
        else:
            out.write(f'Host: {dhost} - Host is down\n')

    def syn_scan(self, dnetwork=None, dhost=None, dport=None, scan_type=None, scan_id=None, *args, **kwargs):
        logger.info('SYN scan started...')
        logger.debug(f'{dnetwork=} {dhost=} {dport=} {scan_type=} {scan_id=}')

        net, ports = self._preprocess_scan_arguments(
            dnetwork=dnetwork,
            dhost=dhost,
            dport=dport,
        )

        out = open(f'scans/scan_{scan_id}.txt', 'w')
        out.write('---- SYN Scan started ----\n')
        out.flush()

        logger.debug(f'{net}')
        for host in net:
            out.write(f"Scanning Host '{host}'\n")
            out.flush()
            for port in ports:
                self._syn_host_scan(host, port, out)

        out.write('-------- FINISHED --------')
        out.close()

    def tcp_scan(self, dnetwork=None, dhost=None, dport=None, scan_type=None, scan_id=None, *args, **kwargs):
        logger.info('TCP scan started...')
        logger.debug(f'{dnetwork=} {dhost=} {dport=} {scan_type=} {scan_id=}')

        net, ports = self._preprocess_scan_arguments(
            dnetwork=dnetwork,
            dhost=dhost,
            dport=dport,
        )

        out = open(f'scans/scan_{scan_id}.txt', 'w')
        out.write('---- TCP Scan started ----\n')
        out.flush()

        logger.debug(f'{net}')
        for host in net:
            out.write(f"Scanning Host '{host}'\n")
            out.flush()
            for port in ports:
                self._tcp_host_scan(host, port, out)

        out.write('-------- FINISHED --------')
        out.close()

    def udp_scan(self, dnetwork=None, dhost=None, dport=None, scan_type=None, scan_id=None, *args, **kwargs):
        logger.info('UDP scan started...')
        logger.debug(f'{dnetwork=} {dhost=} {dport=} {scan_type=} {scan_id=}')

        net, ports = self._preprocess_scan_arguments(
            dnetwork=dnetwork,
            dhost=dhost,
            dport=dport,
        )

        out = open(f'scans/scan_{scan_id}.txt', 'w')
        out.write('---- UDP Scan started ----\n')
        out.flush()

        logger.debug(f'{net}')
        for host in net:
            out.write(f"Scanning Host '{host}'\n")

            for port in ports:
                self._udp_host_scan(host, port, out)
                out.flush()

        out.write('-------- FINISHED --------')
        out.close()

    def icmp_scan(self, dnetwork=None, dhost=None, dport=None, scan_type=None, scan_id=None, *args, **kwargs):
        logger.info('ICMP scan started...')
        logger.debug(f'{dnetwork=} {dhost=} {dport=} {scan_type=} {scan_id=}')

        net, ports = self._preprocess_scan_arguments(
            dnetwork=dnetwork,
            dhost=dhost,
            dport=dport,
        )

        out = open(f'scans/scan_{scan_id}.txt', 'w')
        out.write('---- ICMP Scan started ----\n')
        out.flush()

        logger.debug(f'{net}')
        for host in net:
            self._icmp_host_scan(host, out)
            out.flush()

        out.write('-------- FINISHED --------')
        out.close()


if __name__ == '__main__':
    s = Scanner()
    s.syn_scan('127.0.0.1', 5432)
