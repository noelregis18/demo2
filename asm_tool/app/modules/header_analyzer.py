import requests
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL verification warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class HeaderAnalyzer:
    def __init__(self, domain):
        self.domain = domain
        self.headers = {}
        self.security_headers = {
            'Strict-Transport-Security': {
                'required': True,
                'description': 'Enforces HTTPS connections',
                'recommended': 'max-age=31536000; includeSubDomains; preload'
            },
            'X-Frame-Options': {
                'required': True,
                'description': 'Prevents clickjacking attacks',
                'recommended': 'DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'required': True,
                'description': 'Prevents MIME type sniffing',
                'recommended': 'nosniff'
            },
            'X-XSS-Protection': {
                'required': True,
                'description': 'Enables browser XSS filtering',
                'recommended': '1; mode=block'
            },
            'Content-Security-Policy': {
                'required': False,
                'description': 'Controls resource loading',
                'recommended': "default-src 'self'"
            },
            'Referrer-Policy': {
                'required': False,
                'description': 'Controls referrer information',
                'recommended': 'strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'required': False,
                'description': 'Controls browser features',
                'recommended': 'geolocation=(), microphone=(), camera=()'
            }
        }
    
    def analyze(self):
        """
        Analyze HTTP security headers
        """
        try:
            # Try HTTPS first
            response = self._make_request('https')
            if response:
                self.headers = dict(response.headers)
                return self._analyze_headers()
            
            # Fallback to HTTP
            response = self._make_request('http')
            if response:
                self.headers = dict(response.headers)
                return self._analyze_headers()
            
            return {'error': 'Could not connect to the domain'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _make_request(self, protocol):
        """
        Make HTTP request to the domain
        """
        try:
            url = f'{protocol}://{self.domain}'
            response = requests.get(url, verify=False, timeout=10)
            return response
        except:
            return None
    
    def _analyze_headers(self):
        """
        Analyze security headers
        """
        results = {
            'headers': {},
            'missing': [],
            'issues': [],
            'score': 100
        }
        
        # Check each security header
        for header, info in self.security_headers.items():
            header_value = self.headers.get(header, '')
            
            if not header_value and info['required']:
                results['missing'].append({
                    'header': header,
                    'description': info['description'],
                    'recommended': info['recommended']
                })
                results['score'] -= 10
            
            results['headers'][header] = {
                'value': header_value,
                'status': 'present' if header_value else 'missing',
                'required': info['required'],
                'description': info['description'],
                'recommended': info['recommended']
            }
        
        # Check for additional security headers
        for header, value in self.headers.items():
            if header.lower().startswith(('x-', 'content-', 'strict-', 'permissions-')):
                if header not in results['headers']:
                    results['headers'][header] = {
                        'value': value,
                        'status': 'present',
                        'required': False,
                        'description': 'Additional security header',
                        'recommended': None
                    }
        
        # Ensure score doesn't go below 0
        results['score'] = max(0, results['score'])
        
        return results 