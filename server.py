#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              WEBCAM SCANNER - PROXY SERVER v3.0              ║
║   Servidor proxy local para bypassear restricciones CORS     ║
║   + Módulo de identificación de cámaras y credenciales       ║
║                                                              ║
║   USO:  python server.py                                     ║
║   URL:  http://localhost:8888                                ║
╚══════════════════════════════════════════════════════════════╝
"""

import http.server
import json
import socket
import socketserver
import threading
import urllib.request
import urllib.error
import os
import sys
import time
import re
import concurrent.futures
from urllib.parse import urlparse, parse_qs


PORT = 8888
SCAN_TIMEOUT = 2


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


# ═══════════════════════════════════════════════════════════════
#  BASE DE DATOS DE FINGERPRINTS DE CÁMARAS + CREDENCIALES
# ═══════════════════════════════════════════════════════════════

CAMERA_DB = [
    {
        'brand': 'Hikvision',
        'models': ['DS-2CD', 'DS-2DE', 'DS-7', 'DS-8', 'DS-9', 'IPC-'],
        'signatures': {
            'server': ['hikvision', 'davinci', 'dnvrs', 'webs'],
            'title': ['hikvision', 'hik-connect', 'ivms-', 'dvr login', 'web client test'],
            'body': ['hikvision', 'doc/page/login.asp', '/SDK/', 'webComponents', 'digest realm="IP Camera"', 'hik-connect'],
            'headers': ['App-webs', 'davinci'],
            'paths': ['/ISAPI/System/deviceInfo', '/doc/page/login.asp', '/SDK/activateStatus'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': '12345'},
            {'user': 'admin', 'pass': 'admin12345'},
            {'user': 'admin', 'pass': 'hikvision'},
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'Post-2015 requiere activación. Password por defecto en modelos antiguos: 12345'
    },
    {
        'brand': 'Dahua',
        'models': ['IPC-HDW', 'IPC-HFW', 'DH-', 'XVR', 'NVR', 'HAC-'],
        'signatures': {
            'server': ['dahua', 'dh-', 'dhipserver'],
            'title': ['dahua', 'web service', 'smart pss', 'login to device'],
            'body': ['dahua', 'DhWebClientPlugin', 'DHVideoWEB', '/RPC2', 'realm="Login to'],
            'headers': [],
            'paths': ['/RPC2', '/cgi-bin/magicBox.cgi?action=getDeviceType'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': 'admin123'},
            {'user': 'admin', 'pass': ''},
            {'user': '888888', 'pass': '888888'},
            {'user': '666666', 'pass': '666666'},
        ],
        'notes': 'Modelos nuevos requieren activación. Puertos web: 80, 37777'
    },
    {
        'brand': 'Axis',
        'models': ['AXIS M', 'AXIS P', 'AXIS Q', 'AXIS F', 'AXIS V'],
        'signatures': {
            'server': ['axis', 'boa'],
            'title': ['axis', 'live view', 'axis communications'],
            'body': ['axis communications', '/axis-cgi/', 'axiscam', 'brand=AXIS'],
            'headers': [],
            'paths': ['/axis-cgi/param.cgi', '/axis-cgi/mjpg/video.cgi', '/axis-cgi/basicdeviceinfo.cgi'],
        },
        'default_creds': [
            {'user': 'root', 'pass': 'root'},
            {'user': 'root', 'pass': 'pass'},
            {'user': 'root', 'pass': ''},
            {'user': 'admin', 'pass': 'admin'},
        ],
        'notes': 'AXIS firmware reciente: root sin password hasta primer setup'
    },
    {
        'brand': 'Foscam',
        'models': ['FI89', 'FI98', 'C1', 'C2', 'R2', 'R4', 'SD2'],
        'signatures': {
            'server': ['foscam', 'ipcam', 'netwave'],
            'title': ['foscam', 'ipcam', 'netwave ip camera'],
            'body': ['foscam', 'netwave', 'IPCamera', 'cgi-bin/CGIProxy.fcgi'],
            'headers': ['netwave'],
            'paths': ['/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo', '/get_status.cgi'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': ''},
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': 'foscam'},
        ],
        'notes': 'Modelos antiguos no tienen password por defecto'
    },
    {
        'brand': 'D-Link',
        'models': ['DCS-', 'DCS-930', 'DCS-932', 'DCS-2130', 'DCS-5222'],
        'signatures': {
            'server': ['dlink', 'd-link', 'dcs-'],
            'title': ['d-link', 'dcs-', 'dlink'],
            'body': ['d-link', 'dlink', 'DCS-', 'NIPCA', 'dlink_body'],
            'headers': [],
            'paths': ['/common/info.cgi', '/image/jpeg.cgi', '/video.cgi'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': ''},
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': 'password'},
        ],
        'notes': 'Password vacío por defecto en mayoría de modelos DCS'
    },
    {
        'brand': 'TP-Link',
        'models': ['NC200', 'NC250', 'NC450', 'TAPO C', 'IPC'],
        'signatures': {
            'server': ['tp-link', 'tplink'],
            'title': ['tp-link', 'tplink', 'tapo'],
            'body': ['tp-link', 'tplink', 'TAPO'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': 'password'},
        ],
        'notes': 'Tapo requiere app, no tiene acceso web directo'
    },
    {
        'brand': 'Amcrest',
        'models': ['IP2M', 'IP3M', 'IP4M', 'IP5M', 'IP8M', 'ASH'],
        'signatures': {
            'server': ['amcrest'],
            'title': ['amcrest', 'web service'],
            'body': ['amcrest', 'Amcrest'],
            'headers': [],
            'paths': ['/cgi-bin/magicBox.cgi?action=getDeviceType'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': 'password'},
        ],
        'notes': 'Basado en Dahua. Password por defecto: admin'
    },
    {
        'brand': 'Vivotek',
        'models': ['IP816', 'FD816', 'IB836', 'FD9', 'IB9'],
        'signatures': {
            'server': ['vivotek'],
            'title': ['vivotek', 'network camera'],
            'body': ['vivotek', 'VIVOTEK'],
            'headers': [],
            'paths': ['/cgi-bin/admin/getparam.cgi'],
        },
        'default_creds': [
            {'user': 'root', 'pass': ''},
            {'user': 'root', 'pass': 'root'},
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'Sin password por defecto en muchos modelos'
    },
    {
        'brand': 'Ubiquiti / UniFi',
        'models': ['UVC-G3', 'UVC-G4', 'UniFi Protect', 'AirCam'],
        'signatures': {
            'server': ['ubiquiti', 'ubnt', 'unifi'],
            'title': ['ubiquiti', 'unifi', 'ubnt', 'aircam'],
            'body': ['ubiquiti', 'ubnt', 'UniFi'],
            'headers': ['ubnt'],
            'paths': [],
        },
        'default_creds': [
            {'user': 'ubnt', 'pass': 'ubnt'},
            {'user': 'admin', 'pass': 'admin'},
        ],
        'notes': 'AirCam: ubnt/ubnt. UniFi Protect usa otra autenticación'
    },
    {
        'brand': 'Reolink',
        'models': ['RLC-', 'RLN-', 'E1', 'CX'],
        'signatures': {
            'server': ['reolink'],
            'title': ['reolink'],
            'body': ['reolink', 'Reolink'],
            'headers': [],
            'paths': ['/cgi-bin/api.cgi?cmd=GetDevInfo'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': ''},
            {'user': 'admin', 'pass': 'admin'},
        ],
        'notes': 'Sin password hasta la configuración inicial'
    },
    {
        'brand': 'Panasonic',
        'models': ['WV-', 'BB-', 'BL-'],
        'signatures': {
            'server': ['panasonic', 'wv-'],
            'title': ['panasonic', 'network camera', 'wv-'],
            'body': ['panasonic', 'Panasonic', 'nwcam'],
            'headers': [],
            'paths': ['/cgi-bin/getinfo', '/live/camctrl.html'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': '12345'},
            {'user': 'admin', 'pass': 'admin'},
        ],
        'notes': 'Modelos WV-: admin/12345'
    },
    {
        'brand': 'Samsung / Hanwha',
        'models': ['SNH-', 'SND-', 'SNP-', 'XNP-', 'XND-', 'QNO-'],
        'signatures': {
            'server': ['samsung', 'hanwha', 'wisenet'],
            'title': ['samsung', 'wisenet', 'hanwha', 'smart viewer'],
            'body': ['samsung', 'wisenet', 'Hanwha', 'samsungcctv'],
            'headers': [],
            'paths': ['/home/monitoring.cgi'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': '4321'},
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'Modelos Wisenet antiguos: admin/4321'
    },
    {
        'brand': 'Sony',
        'models': ['SNC-', 'SRG-'],
        'signatures': {
            'server': ['sony'],
            'title': ['sony', 'snc-'],
            'body': ['sony', 'SNC-', 'SonyNetworkCamera'],
            'headers': [],
            'paths': ['/command/inquiry.cgi'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'admin/admin en la mayoría de modelos SNC'
    },
    {
        'brand': 'Bosch',
        'models': ['NBN-', 'NDE-', 'NDS-', 'NDI-', 'NEZ-', 'DINION'],
        'signatures': {
            'server': ['bosch'],
            'title': ['bosch', 'dinion', 'autodome', 'flexidome'],
            'body': ['bosch', 'Bosch Security', 'DINION', 'AUTODOME'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': ''},
            {'user': 'service', 'pass': 'service'},
            {'user': 'user', 'pass': 'user'},
        ],
        'notes': 'Sin password hasta configuración. Service account: service/service'
    },
    {
        'brand': 'Wanscam',
        'models': ['HW', 'JW', 'K'],
        'signatures': {
            'server': ['wanscam', 'vstarcam'],
            'title': ['wanscam', 'vstarcam', 'ip webcam'],
            'body': ['wanscam', 'vstarcam'],
            'headers': [],
            'paths': ['/get_status.cgi', '/web/cgi-bin/hi3510/'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': '888888'},
            {'user': 'admin', 'pass': 'admin'},
        ],
        'notes': 'admin/888888 en muchos modelos chinos genéricos'
    },
    {
        'brand': 'Tenvis',
        'models': ['TH', 'TZ', 'T8'],
        'signatures': {
            'server': ['tenvis', 'ipcam'],
            'title': ['tenvis'],
            'body': ['tenvis'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'admin/admin o sin password'
    },
    {
        'brand': 'Yoosee / CamHi',
        'models': ['GW-'],
        'signatures': {
            'server': ['yoosee', 'camhi'],
            'title': ['yoosee', 'camhi'],
            'body': ['yoosee', 'CamHi', 'Yoosee'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
        ],
        'notes': 'Cámaras genéricas chinas. admin/admin'
    },
    {
        'brand': 'GoPro',
        'models': ['HERO'],
        'signatures': {
            'server': ['gopro'],
            'title': ['gopro'],
            'body': ['gopro', 'GoPro'],
            'headers': [],
            'paths': ['/gp/gpControl'],
        },
        'default_creds': [
            {'user': '', 'pass': 'goprohero'},
        ],
        'notes': 'WiFi password por defecto: goprohero'
    },
    {
        'brand': 'Mobotix',
        'models': ['M', 'S', 'D', 'Q', 'T'],
        'signatures': {
            'server': ['mobotix'],
            'title': ['mobotix'],
            'body': ['mobotix', 'MOBOTIX'],
            'headers': [],
            'paths': ['/control/userimage.html'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'meinsm'},
        ],
        'notes': 'admin/meinsm es el default clásico de Mobotix'
    },
    {
        'brand': 'FLIR / Lorex',
        'models': ['DNR', 'LNB', 'LNR', 'LHV', 'N84'],
        'signatures': {
            'server': ['flir', 'lorex', 'digimerge'],
            'title': ['flir', 'lorex', 'digimerge'],
            'body': ['flir', 'lorex', 'FLIR', 'Lorex', 'Digimerge'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': '000000'},
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'Lorex/FLIR basados en Dahua. admin/admin o admin/000000'
    },
    {
        'brand': 'Pelco',
        'models': ['IME', 'IMP', 'IBP', 'IXE', 'Sarix'],
        'signatures': {
            'server': ['pelco'],
            'title': ['pelco', 'sarix'],
            'body': ['pelco', 'Pelco', 'Sarix'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': 'initial'},
        ],
        'notes': 'admin/admin o admin/initial'
    },
    {
        'brand': 'Geovision',
        'models': ['GV-', 'BL', 'FD', 'MFD'],
        'signatures': {
            'server': ['geovision', 'gv-'],
            'title': ['geovision', 'geo vision', 'gv-'],
            'body': ['geovision', 'GeoVision', 'Geovision', 'gvideo'],
            'headers': [],
            'paths': ['/ssi.cgi/Login.htm'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
        ],
        'notes': 'admin/admin por defecto'
    },
    {
        'brand': 'Trendnet',
        'models': ['TV-IP', 'TPL-'],
        'signatures': {
            'server': ['trendnet'],
            'title': ['trendnet', 'tv-ip'],
            'body': ['trendnet', 'TRENDnet', 'TV-IP'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'admin/admin por defecto'
    },
    {
        'brand': 'Avtech',
        'models': ['AVM', 'AVH', 'AVX', 'DGH'],
        'signatures': {
            'server': ['avtech', 'boa', 'thttpd'],
            'title': ['avtech', 'avm', 'video web server'],
            'body': ['avtech', 'AVTECH', 'video web server', 'dvr_app'],
            'headers': [],
            'paths': ['/cgi-bin/guest/Video.cgi'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'admin/admin. Vulnerabilidades conocidas en firmwares antiguos'
    },
    {
        'brand': 'Grandstream',
        'models': ['GXV', 'GSC'],
        'signatures': {
            'server': ['grandstream', 'gxv'],
            'title': ['grandstream', 'gxv'],
            'body': ['grandstream', 'Grandstream', 'GXV'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
        ],
        'notes': 'admin/admin por defecto'
    },
    {
        'brand': 'ACTi',
        'models': ['ACM-', 'TCM-', 'KCM-', 'E', 'B', 'I', 'A'],
        'signatures': {
            'server': ['acti'],
            'title': ['acti', 'web configurator'],
            'body': ['acti', 'ACTi'],
            'headers': [],
            'paths': ['/cgi-bin/system'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': '123456'},
            {'user': 'Admin', 'pass': '123456'},
        ],
        'notes': 'admin/123456 o Admin/123456'
    },
    {
        'brand': 'ZKTeco',
        'models': ['ZK-'],
        'signatures': {
            'server': ['zkteco', 'zk-'],
            'title': ['zkteco'],
            'body': ['zkteco', 'ZKTeco'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'Sin password por defecto'
    },
    {
        'brand': 'XMEye / Generic Chinese DVR',
        'models': ['HI35', 'NBD', 'XM'],
        'signatures': {
            'server': ['mini_httpd', 'boa', 'goahead', 'thttpd', 'alphapd', 'cross web server'],
            'title': ['dvr', 'nvr', 'web client', 'net surveillance', 'xmeye', 'cms', 'netsurveillance'],
            'body': ['xmeye', 'XMEye', 'NetSurveillance', 'netsurveillance', 'hi35', 'Sofia', 'cross web server', 'dvr_web'],
            'headers': [],
            'paths': ['/Login.htm', '/doc/page/login.asp'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': ''},
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': '12345'},
            {'user': 'admin', 'pass': '123456'},
            {'user': 'admin', 'pass': '888888'},
            {'user': 'default', 'pass': 'tluafed'},
            {'user': 'user', 'pass': 'user'},
        ],
        'notes': 'DVR/NVR genéricos chinos. Probar admin sin password primero. "default/tluafed" es backdoor conocido.'
    },
    {
        'brand': 'ONVIF Compatible',
        'models': [],
        'signatures': {
            'server': ['onvif'],
            'title': ['onvif'],
            'body': ['onvif', 'ONVIF'],
            'headers': [],
            'paths': ['/onvif/device_service'],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'Dispositivo compatible ONVIF. Credenciales dependen del fabricante.'
    },
    {
        'brand': 'Edimax',
        'models': ['IC-'],
        'signatures': {
            'server': ['edimax'],
            'title': ['edimax', 'ic-'],
            'body': ['edimax', 'Edimax'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': '1234'},
        ],
        'notes': 'admin/1234 por defecto'
    },
    {
        'brand': 'Linksys',
        'models': ['WVC'],
        'signatures': {
            'server': ['linksys'],
            'title': ['linksys', 'wvc'],
            'body': ['linksys', 'Linksys'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'admin'},
            {'user': '', 'pass': 'admin'},
        ],
        'notes': 'admin/admin o sin usuario con password admin'
    },
    {
        'brand': 'Netgear / Arlo',
        'models': ['VMS', 'VMC', 'Arlo'],
        'signatures': {
            'server': ['netgear', 'arlo'],
            'title': ['netgear', 'arlo'],
            'body': ['netgear', 'arlo', 'Arlo', 'NETGEAR'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'password'},
        ],
        'notes': 'admin/password en productos Netgear'
    },
    {
        'brand': 'Swann',
        'models': ['NVR', 'DVR', 'NHD'],
        'signatures': {
            'server': ['swann'],
            'title': ['swann'],
            'body': ['swann', 'Swann'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': '12345'},
            {'user': 'admin', 'pass': ''},
        ],
        'notes': 'admin/12345'
    },
    {
        'brand': 'Milesight',
        'models': ['MS-', 'C'],
        'signatures': {
            'server': ['milesight'],
            'title': ['milesight'],
            'body': ['milesight', 'Milesight'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': 'ms1234'},
        ],
        'notes': 'admin/ms1234 por defecto'
    },
    {
        'brand': 'Honeywell',
        'models': ['HE', 'HD', 'HCD'],
        'signatures': {
            'server': ['honeywell'],
            'title': ['honeywell', 'ademco'],
            'body': ['honeywell', 'Honeywell'],
            'headers': [],
            'paths': [],
        },
        'default_creds': [
            {'user': 'admin', 'pass': '1234'},
            {'user': 'admin', 'pass': 'admin'},
        ],
        'notes': 'admin/1234 o admin/admin'
    },
]


# ═══════════════════════════════════════════════════════════════
#  FUNCIONES DE FINGERPRINTING
# ═══════════════════════════════════════════════════════════════

def fetch_camera_info(ip, port, timeout=3):
    """Obtiene toda la información posible del servidor HTTP"""
    info = {
        'ip': ip,
        'port': port,
        'server': '',
        'title': '',
        'headers': {},
        'body_snippet': '',
        'status_code': 0,
        'content_type': '',
        'www_authenticate': '',
        'extra_paths': {},
    }

    # 1. GET principal
    try:
        url = f"http://{ip}:{port}/"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            info['status_code'] = resp.status
            info['server'] = resp.headers.get('Server', '')
            info['content_type'] = resp.headers.get('Content-Type', '')
            info['www_authenticate'] = resp.headers.get('WWW-Authenticate', '')
            # Guardar todos los headers
            for key in resp.headers:
                info['headers'][key] = resp.headers[key]
            try:
                body = resp.read(8192).decode('utf-8', errors='ignore')
                info['body_snippet'] = body
                title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    info['title'] = title_match.group(1).strip()[:200]
            except:
                pass
    except urllib.error.HTTPError as e:
        info['status_code'] = e.code
        info['server'] = e.headers.get('Server', '') if e.headers else ''
        info['www_authenticate'] = e.headers.get('WWW-Authenticate', '') if e.headers else ''
        if e.headers:
            for key in e.headers:
                info['headers'][key] = e.headers[key]
        try:
            body = e.read(4096).decode('utf-8', errors='ignore')
            info['body_snippet'] = body
            title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
            if title_match:
                info['title'] = title_match.group(1).strip()[:200]
        except:
            pass
    except:
        pass

    # 2. Probar paths que revelan modelo
    identify_paths = [
        '/ISAPI/System/deviceInfo',              # Hikvision
        '/cgi-bin/magicBox.cgi?action=getDeviceType',  # Dahua/Amcrest
        '/axis-cgi/basicdeviceinfo.cgi',         # Axis
        '/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo', # Foscam
        '/cgi-bin/api.cgi?cmd=GetDevInfo',       # Reolink
        '/onvif/device_service',                 # ONVIF
        '/common/info.cgi',                      # D-Link
        '/System/deviceInfo',                    # Generic ISAPI
    ]

    for path in identify_paths:
        try:
            url = f"http://{ip}:{port}{path}"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            with urllib.request.urlopen(req, timeout=min(timeout, 2)) as resp:
                data = resp.read(4096).decode('utf-8', errors='ignore')
                info['extra_paths'][path] = {
                    'status': resp.status,
                    'body': data[:2000],
                    'content_type': resp.headers.get('Content-Type', ''),
                }
        except urllib.error.HTTPError as e:
            if e.code == 401:
                info['extra_paths'][path] = {
                    'status': 401,
                    'body': '',
                    'note': 'Auth required - path exists',
                }
        except:
            pass

    return info


def identify_camera(camera_info):
    """Identifica la cámara comparando contra la base de datos"""
    results = []

    all_text = ' '.join([
        camera_info.get('server', ''),
        camera_info.get('title', ''),
        camera_info.get('body_snippet', '')[:3000],
        camera_info.get('www_authenticate', ''),
        ' '.join(camera_info.get('headers', {}).values()),
        ' '.join(ep.get('body', '') for ep in camera_info.get('extra_paths', {}).values()),
    ]).lower()

    server_lower = camera_info.get('server', '').lower()
    title_lower = camera_info.get('title', '').lower()

    for cam in CAMERA_DB:
        score = 0
        matched_signatures = []

        # Check server header
        for sig in cam['signatures'].get('server', []):
            if sig.lower() in server_lower:
                score += 30
                matched_signatures.append(f"server: {sig}")

        # Check title
        for sig in cam['signatures'].get('title', []):
            if sig.lower() in title_lower:
                score += 25
                matched_signatures.append(f"title: {sig}")

        # Check body content
        for sig in cam['signatures'].get('body', []):
            if sig.lower() in all_text:
                score += 20
                matched_signatures.append(f"body: {sig}")

        # Check extra headers
        for sig in cam['signatures'].get('headers', []):
            header_text = ' '.join(camera_info.get('headers', {}).values()).lower()
            if sig.lower() in header_text:
                score += 25
                matched_signatures.append(f"header: {sig}")

        # Check if probe paths responded
        for sig_path in cam['signatures'].get('paths', []):
            if sig_path in camera_info.get('extra_paths', {}):
                ep = camera_info['extra_paths'][sig_path]
                if ep.get('status', 0) in [200, 401]:
                    score += 35
                    matched_signatures.append(f"path: {sig_path} ({ep.get('status')})")

        if score > 0:
            # Try to extract model from content
            model = extract_model(all_text, cam)
            results.append({
                'brand': cam['brand'],
                'model': model,
                'score': score,
                'confidence': 'HIGH' if score >= 50 else 'MEDIUM' if score >= 25 else 'LOW',
                'matched_signatures': matched_signatures,
                'default_creds': cam['default_creds'],
                'notes': cam['notes'],
            })

    # Sort by score
    results.sort(key=lambda x: x['score'], reverse=True)
    return results


def extract_model(text, cam_entry):
    """Intenta extraer el modelo específico del texto"""
    # Try to find model patterns from the camera DB
    for model in cam_entry.get('models', []):
        pattern = re.compile(re.escape(model) + r'[\w\-\.]*', re.IGNORECASE)
        match = pattern.search(text)
        if match:
            return match.group(0)

    # Generic model extraction patterns
    patterns = [
        r'model["\s:=]+([A-Z0-9][\w\-\.]+)',
        r'deviceModel["\s:=]+([A-Z0-9][\w\-\.]+)',
        r'product["\s:=]+([A-Z0-9][\w\-\.]+)',
        r'Device Type["\s:=]+([A-Z0-9][\w\-\.]+)',
    ]
    for p in patterns:
        match = re.search(p, text, re.IGNORECASE)
        if match:
            return match.group(1)

    return 'Unknown Model'


# ═══════════════════════════════════════════════════════════════
#  FUNCIONES DE RED
# ═══════════════════════════════════════════════════════════════

def ip_to_long(ip):
    parts = list(map(int, ip.split('.')))
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def long_to_ip(n):
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def scan_port(ip, port, timeout):
    """Escaneo TCP real usando sockets"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            banner_info = get_http_banner(ip, port, timeout)
            return {
                'ip': ip,
                'port': port,
                'open': True,
                'banner': banner_info.get('server', ''),
                'title': banner_info.get('title', ''),
                'status_code': banner_info.get('status_code', 0),
                'content_type': banner_info.get('content_type', ''),
                'is_camera': banner_info.get('is_camera', False),
            }
        return {'ip': ip, 'port': port, 'open': False}
    except socket.timeout:
        return {'ip': ip, 'port': port, 'open': False, 'reason': 'timeout'}
    except Exception as e:
        return {'ip': ip, 'port': port, 'open': False, 'reason': str(e)}


def get_http_banner(ip, port, timeout):
    """Intenta obtener información HTTP del servidor"""
    info = {}
    try:
        url = f"http://{ip}:{port}/"
        req = urllib.request.Request(url, method='GET')
        req.add_header('User-Agent', 'Mozilla/5.0 (compatible; WebCamScanner/3.0)')
        with urllib.request.urlopen(req, timeout=timeout) as response:
            info['status_code'] = response.status
            info['server'] = response.headers.get('Server', 'Unknown')
            info['content_type'] = response.headers.get('Content-Type', '')
            try:
                body = response.read(4096).decode('utf-8', errors='ignore')
                title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    info['title'] = title_match.group(1).strip()[:100]
            except:
                pass

            camera_keywords = [
                'camera', 'cam', 'ipcam', 'webcam', 'dvr', 'nvr',
                'hikvision', 'dahua', 'axis', 'foscam', 'amcrest',
                'vivotek', 'ubiquiti', 'reolink', 'wyze', 'nest',
                'mjpg', 'mjpeg', 'video', 'stream', 'surveillance',
                'cctv', 'security', 'viewer', 'live view', 'netcam',
                'gopro', 'dlink', 'd-link', 'tp-link', 'tenvis',
                'wanscam', 'sricam', 'yoosee', 'v380', 'xmeye',
                'mini_httpd', 'boa', 'goahead', 'thttpd'
            ]
            all_text = (info.get('server', '') + ' ' + info.get('title', '') + ' ' + info.get('content_type', '')).lower()
            info['is_camera'] = any(kw in all_text for kw in camera_keywords)

    except urllib.error.HTTPError as e:
        info['status_code'] = e.code
        info['server'] = e.headers.get('Server', 'Unknown') if e.headers else 'Unknown'
        camera_servers = ['mini_httpd', 'boa', 'thttpd', 'goahead', 'hikvision', 'dahua']
        info['is_camera'] = any(cs in info['server'].lower() for cs in camera_servers)
    except:
        pass
    return info


# ═══════════════════════════════════════════════════════════════
#  ESTADO GLOBAL PARA ESCANEO ASYNC
# ═══════════════════════════════════════════════════════════════

scan_state = {
    'active': False,
    'scanned': 0,
    'total': 0,
    'results': [],
    'current_ip': '',
    'start_time': 0,
    'stop_requested': False,
}
scan_lock = threading.Lock()


def async_scan_worker(ip_start, ip_end, port, timeout, max_threads):
    """Worker que corre en background y actualiza scan_state"""
    global scan_state
    start_long = ip_to_long(ip_start)
    end_long = ip_to_long(ip_end)
    ips = [long_to_ip(i) for i in range(start_long, end_long + 1)]

    with scan_lock:
        scan_state['active'] = True
        scan_state['scanned'] = 0
        scan_state['total'] = len(ips)
        scan_state['results'] = []
        scan_state['start_time'] = time.time()
        scan_state['stop_requested'] = False

    def worker(ip):
        if scan_state['stop_requested']:
            return None
        with scan_lock:
            scan_state['current_ip'] = ip
        result = scan_port(ip, port, timeout)
        with scan_lock:
            scan_state['scanned'] += 1
            if result['open']:
                result['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S')
                scan_state['results'].append(result)
                print(f"  {Colors.CYAN}[FOUND]{Colors.RESET} {Colors.GREEN}{ip}:{port}{Colors.RESET} "
                      f"- Server: {result.get('banner', 'N/A')} "
                      f"| Title: {result.get('title', 'N/A')} "
                      f"{'📷' if result.get('is_camera') else ''}")
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for ip in ips:
            if scan_state['stop_requested']:
                break
            futures.append(executor.submit(worker, ip))
        for f in concurrent.futures.as_completed(futures):
            if scan_state['stop_requested']:
                executor.shutdown(wait=False, cancel_futures=True)
                break

    with scan_lock:
        scan_state['active'] = False

    found = len(scan_state['results'])
    elapsed = time.time() - scan_state['start_time']
    print(f"\n  {Colors.GREEN}[DONE]{Colors.RESET} Escaneo completado: "
          f"{scan_state['scanned']}/{scan_state['total']} escaneadas, "
          f"{found} encontradas en {elapsed:.1f}s")


# ═══════════════════════════════════════════════════════════════
#  HTTP HANDLER
# ═══════════════════════════════════════════════════════════════

class ScannerHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        try:
            msg = str(args[0]) if args else ''
            if '/api/' in msg and '/api/scan/status' not in msg:
                print(f"  {Colors.DIM}[HTTP] {format % args}{Colors.RESET}")
        except:
            pass

    def send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With')
        self.send_header('Access-Control-Max-Age', '86400')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # ============ API ENDPOINTS ============

        if path == '/api/ping':
            self.send_json({'status': 'ok', 'server': 'WebCam Scanner Proxy', 'version': '3.0'})

        elif path == '/api/scan':
            ip = params.get('ip', [''])[0]
            port = int(params.get('port', ['80'])[0])
            timeout = float(params.get('timeout', ['2'])[0])
            if not ip:
                self.send_json({'error': 'IP requerida'}, 400)
                return
            result = scan_port(ip, port, timeout)
            self.send_json(result)

        elif path == '/api/scan/start':
            ip_start = params.get('start', [''])[0]
            ip_end = params.get('end', [''])[0]
            port = int(params.get('port', ['80'])[0])
            timeout = float(params.get('timeout', ['2'])[0])
            threads = int(params.get('threads', ['50'])[0])
            if not ip_start or not ip_end:
                self.send_json({'error': 'Se requiere start y end'}, 400)
                return
            if scan_state['active']:
                self.send_json({'error': 'Ya hay un escaneo en curso', 'active': True}, 409)
                return
            t = threading.Thread(
                target=async_scan_worker,
                args=(ip_start, ip_end, port, timeout, threads),
                daemon=True
            )
            t.start()
            start_long = ip_to_long(ip_start)
            end_long = ip_to_long(ip_end)
            total = end_long - start_long + 1
            print(f"\n  {Colors.YELLOW}[SCAN]{Colors.RESET} Iniciando escaneo: "
                  f"{ip_start} → {ip_end} ({total} hosts) Puerto:{port}")
            self.send_json({
                'status': 'started',
                'total': total,
                'port': port,
                'threads': threads,
            })

        elif path == '/api/scan/status':
            with scan_lock:
                elapsed = time.time() - scan_state['start_time'] if scan_state['start_time'] else 0
                speed = scan_state['scanned'] / elapsed if elapsed > 0 else 0
                offset = int(params.get('offset', ['0'])[0])
                new_results = scan_state['results'][offset:]
                self.send_json({
                    'active': scan_state['active'],
                    'scanned': scan_state['scanned'],
                    'total': scan_state['total'],
                    'found': len(scan_state['results']),
                    'current_ip': scan_state['current_ip'],
                    'elapsed': round(elapsed, 1),
                    'speed': round(speed, 1),
                    'new_results': new_results,
                    'results_offset': offset + len(new_results),
                })

        elif path == '/api/scan/stop':
            with scan_lock:
                scan_state['stop_requested'] = True
            print(f"  {Colors.RED}[STOP]{Colors.RESET} Escaneo detenido por el usuario")
            self.send_json({'status': 'stopping'})

        elif path == '/api/scan/results':
            with scan_lock:
                self.send_json({
                    'results': scan_state['results'],
                    'total_found': len(scan_state['results']),
                })

        elif path == '/api/identify':
            # ══════ IDENTIFICAR CÁMARA ══════
            ip = params.get('ip', [''])[0]
            port = int(params.get('port', ['80'])[0])
            timeout = float(params.get('timeout', ['4'])[0])
            if not ip:
                self.send_json({'error': 'IP requerida'}, 400)
                return

            print(f"  {Colors.MAGENTA}[ID]{Colors.RESET} Identificando cámara: {ip}:{port}")

            cam_info = fetch_camera_info(ip, port, timeout)
            matches = identify_camera(cam_info)

            result = {
                'ip': ip,
                'port': port,
                'server': cam_info.get('server', ''),
                'title': cam_info.get('title', ''),
                'status_code': cam_info.get('status_code', 0),
                'www_authenticate': cam_info.get('www_authenticate', ''),
                'headers_count': len(cam_info.get('headers', {})),
                'paths_probed': len(cam_info.get('extra_paths', {})),
                'paths_found': [p for p, v in cam_info.get('extra_paths', {}).items()
                                if v.get('status', 0) in [200, 401]],
                'matches': matches[:5],  # Top 5 matches
                'identified': len(matches) > 0,
                'best_match': matches[0] if matches else None,
            }

            if matches:
                best = matches[0]
                print(f"  {Colors.MAGENTA}[ID]{Colors.RESET} → {Colors.BOLD}{best['brand']}{Colors.RESET} "
                      f"({best['model']}) [{best['confidence']}] "
                      f"Creds: {len(best['default_creds'])}")
            else:
                print(f"  {Colors.MAGENTA}[ID]{Colors.RESET} → No identificada")

            self.send_json(result)

        elif path == '/api/identify/batch':
            # Identificar múltiples IPs
            ips_param = params.get('ips', [''])[0]
            port = int(params.get('port', ['80'])[0])
            if not ips_param:
                self.send_json({'error': 'Se requiere parámetro ips (separados por coma)'}, 400)
                return
            ips = [ip.strip() for ip in ips_param.split(',') if ip.strip()]
            batch_results = []
            for ip in ips[:20]:  # Max 20
                try:
                    cam_info = fetch_camera_info(ip, port, 3)
                    matches = identify_camera(cam_info)
                    batch_results.append({
                        'ip': ip,
                        'port': port,
                        'server': cam_info.get('server', ''),
                        'title': cam_info.get('title', ''),
                        'identified': len(matches) > 0,
                        'best_match': matches[0] if matches else None,
                    })
                except:
                    batch_results.append({'ip': ip, 'error': 'Failed'})
            self.send_json({'results': batch_results})

        elif path == '/api/creds/db':
            # Retornar la base de datos completa de credenciales
            db_summary = []
            for cam in CAMERA_DB:
                db_summary.append({
                    'brand': cam['brand'],
                    'models': cam['models'],
                    'default_creds': cam['default_creds'],
                    'notes': cam['notes'],
                })
            self.send_json({'cameras': db_summary, 'total': len(db_summary)})

        elif path == '/api/proxy':
            url = params.get('url', [''])[0]
            if not url:
                self.send_json({'error': 'URL requerida'}, 400)
                return
            self.proxy_request(url)

        elif path == '/api/probe':
            ip = params.get('ip', [''])[0]
            port = int(params.get('port', ['80'])[0])
            timeout = float(params.get('timeout', ['3'])[0])
            cam_paths = [
                '/', '/mjpg/video.mjpg', '/video.mjpg',
                '/cgi-bin/mjpg/video.cgi', '/axis-cgi/mjpg/video.cgi',
                '/snap.jpg', '/snapshot.jpg', '/cgi-bin/snapshot.cgi',
                '/image/jpeg.cgi', '/jpg/image.jpg', '/webcapture.jpg',
                '/shot.jpg', '/still.jpg', '/capture.jpg', '/live.jpg',
                '/video.cgi', '/videostream.cgi',
                '/Streaming/channels/1/picture',
                '/onvif/snapshot', '/cgi-bin/camera',
            ]
            found_paths = []
            for cam_path in cam_paths:
                try:
                    url = f"http://{ip}:{port}{cam_path}"
                    req = urllib.request.Request(url)
                    req.add_header('User-Agent', 'Mozilla/5.0')
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        ct = resp.headers.get('Content-Type', '')
                        cl = resp.headers.get('Content-Length', '0')
                        found_paths.append({
                            'path': cam_path,
                            'status': resp.status,
                            'content_type': ct,
                            'content_length': cl,
                            'is_image': 'image' in ct,
                            'is_video': 'video' in ct or 'mjpg' in ct or 'mjpeg' in ct,
                        })
                except:
                    pass
            self.send_json({'ip': ip, 'port': port, 'paths_found': found_paths})

        elif path == '/':
            self.path = '/index.html'
            super().do_GET()
        else:
            super().do_GET()

    def proxy_request(self, url):
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (compatible; WebCamScanner/3.0)')
            with urllib.request.urlopen(req, timeout=5) as response:
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
                data = response.read(5 * 1024 * 1024)
                self.send_response(200)
                self.send_cors_headers()
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('X-Proxied-URL', url)
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_cors_headers()
            self.end_headers()
        except Exception as e:
            self.send_json({'error': str(e), 'url': url}, 502)

    def send_json(self, data, status=200):
        response = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_cors_headers()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def banner():
    print(f"""{Colors.GREEN}
    ╔══════════════════════════════════════════════════════════╗
    ║   {Colors.BOLD}██╗    ██╗███████╗██████╗  ██████╗ █████╗ ███╗   ███╗{Colors.RESET}{Colors.GREEN}  ║
    ║   {Colors.BOLD}██║    ██║██╔════╝██╔══██╗██╔════╝██╔══██╗████╗ ████║{Colors.RESET}{Colors.GREEN}  ║
    ║   {Colors.BOLD}██║ █╗ ██║█████╗  ██████╔╝██║     ███████║██╔████╔██║{Colors.RESET}{Colors.GREEN}  ║
    ║   {Colors.BOLD}██║███╗██║██╔══╝  ██╔══██╗██║     ██╔══██║██║╚██╔╝██║{Colors.RESET}{Colors.GREEN}  ║
    ║   {Colors.BOLD}╚███╔███╔╝███████╗██████╔╝╚██████╗██║  ██║██║ ╚═╝ ██║{Colors.RESET}{Colors.GREEN}  ║
    ║   {Colors.BOLD} ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝{Colors.RESET}{Colors.GREEN}  ║
    ║                                                          ║
    ║           {Colors.CYAN}PROXY SERVER v3.0 - CORS BYPASS{Colors.GREEN}              ║
    ║       {Colors.MAGENTA}+ Camera Fingerprinting & Credentials DB{Colors.GREEN}        ║
    ╚══════════════════════════════════════════════════════════╝
    {Colors.RESET}""")


def main():
    banner()
    if not os.path.exists('index.html'):
        print(f"  {Colors.RED}[ERROR]{Colors.RESET} No se encontró index.html en el directorio actual")
        sys.exit(1)

    server = ThreadedHTTPServer(('0.0.0.0', PORT), ScannerHandler)

    print(f"  {Colors.GREEN}[OK]{Colors.RESET} Servidor iniciado en {Colors.BOLD}http://localhost:{PORT}{Colors.RESET}")
    print(f"  {Colors.GREEN}[OK]{Colors.RESET} Proxy CORS habilitado")
    print(f"  {Colors.GREEN}[OK]{Colors.RESET} Escaneo TCP real con sockets")
    print(f"  {Colors.GREEN}[OK]{Colors.RESET} Camera Fingerprinting: {Colors.BOLD}{len(CAMERA_DB)} marcas{Colors.RESET} en base de datos")
    print()
    print(f"  {Colors.YELLOW}Endpoints:{Colors.RESET}")
    print(f"  {Colors.DIM}├── GET  /                          → Interfaz web{Colors.RESET}")
    print(f"  {Colors.DIM}├── GET  /api/ping                  → Health check{Colors.RESET}")
    print(f"  {Colors.DIM}├── GET  /api/scan?ip=&port=        → Escanear 1 IP{Colors.RESET}")
    print(f"  {Colors.DIM}├── GET  /api/scan/start?...        → Escaneo de rango{Colors.RESET}")
    print(f"  {Colors.DIM}├── GET  /api/scan/status           → Estado del escaneo{Colors.RESET}")
    print(f"  {Colors.DIM}├── GET  /api/scan/stop             → Detener escaneo{Colors.RESET}")
    print(f"  {Colors.DIM}├── GET  /api/identify?ip=&port=    → {Colors.MAGENTA}Identificar cámara{Colors.RESET}")
    print(f"  {Colors.DIM}├── GET  /api/identify/batch?ips=   → {Colors.MAGENTA}Identificar lote{Colors.RESET}")
    print(f"  {Colors.DIM}├── GET  /api/creds/db              → {Colors.MAGENTA}Base de credenciales{Colors.RESET}")
    print(f"  {Colors.DIM}├── GET  /api/proxy?url=            → Proxy CORS{Colors.RESET}")
    print(f"  {Colors.DIM}└── GET  /api/probe?ip=&port=       → Detectar rutas{Colors.RESET}")
    print()
    print(f"  {Colors.CYAN}Presiona Ctrl+C para detener{Colors.RESET}")
    print(f"  {'─' * 56}")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.RED}[STOP]{Colors.RESET} Servidor detenido")
        server.shutdown()


if __name__ == '__main__':
    main()
