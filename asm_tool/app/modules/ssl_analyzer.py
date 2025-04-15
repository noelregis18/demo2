import ssl
import socket
import OpenSSL
from datetime import datetime
import requests
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL verification warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class SSLAnalyzer:
    def __init__(self, domain):
        self.domain = domain
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
    
    def analyze(self):
        """
        Analyze SSL/TLS configuration
        """
        try:
            # Get certificate information
            cert_info = self._get_certificate_info()
            
            # Check supported protocols
            protocols = self._check_protocols()
            
            # Check cipher suites
            ciphers = self._check_ciphers()
            
            # Check for common vulnerabilities
            vulnerabilities = self._check_vulnerabilities()
            
            return {
                'certificate': cert_info,
                'protocols': protocols,
                'ciphers': ciphers,
                'vulnerabilities': vulnerabilities
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_certificate_info(self):
        """
        Get SSL certificate information
        """
        try:
            with socket.create_connection((self.domain, 443)) as sock:
                with self.context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    
                    # Get certificate details
                    subject = dict(x509.get_subject().get_components())
                    issuer = dict(x509.get_issuer().get_components())
                    
                    not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
                    not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    
                    return {
                        'subject': {
                            'common_name': subject.get(b'CN', b'').decode('utf-8'),
                            'organization': subject.get(b'O', b'').decode('utf-8'),
                            'country': subject.get(b'C', b'').decode('utf-8')
                        },
                        'issuer': {
                            'common_name': issuer.get(b'CN', b'').decode('utf-8'),
                            'organization': issuer.get(b'O', b'').decode('utf-8'),
                            'country': issuer.get(b'C', b'').decode('utf-8')
                        },
                        'valid_from': not_before.isoformat(),
                        'valid_until': not_after.isoformat(),
                        'version': x509.get_version(),
                        'serial_number': hex(x509.get_serial_number())
                    }
                    
        except Exception as e:
            return {'error': str(e)}
    
    def _check_protocols(self):
        """
        Check supported SSL/TLS protocols
        """
        protocols = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1.0': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        for protocol in protocols.keys():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.minimum_version = getattr(ssl, f'PROTOCOL_{protocol}')
                context.maximum_version = getattr(ssl, f'PROTOCOL_{protocol}')
                
                with socket.create_connection((self.domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        protocols[protocol] = True
            except:
                continue
        
        return protocols
    
    def _check_ciphers(self):
        """
        Check supported cipher suites
        """
        try:
            with socket.create_connection((self.domain, 443)) as sock:
                with self.context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cipher = ssock.cipher()
                    return {
                        'name': cipher[0],
                        'version': cipher[1],
                        'bits': cipher[2]
                    }
        except:
            return None
    
    def _check_vulnerabilities(self):
        """
        Check for common SSL/TLS vulnerabilities
        """
        vulnerabilities = {
            'heartbleed': False,
            'poodle': False,
            'beast': False,
            'freak': False,
            'logjam': False
        }
        
        # Check for Heartbleed
        try:
            response = requests.get(f'https://{self.domain}', verify=False, timeout=5)
            if 'heartbleed' in response.headers.get('server', '').lower():
                vulnerabilities['heartbleed'] = True
        except:
            pass
        
        # Check for POODLE
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    vulnerabilities['poodle'] = True
        except:
            pass
        
        # Check for BEAST
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.set_ciphers('RC4')
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    vulnerabilities['beast'] = True
        except:
            pass
        
        return vulnerabilities 