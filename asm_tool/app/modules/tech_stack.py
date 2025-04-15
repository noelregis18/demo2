import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL verification warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class TechStackDetector:
    def __init__(self, domain):
        self.domain = domain
        self.technologies = set()
        self.headers = {}
        self.html = ''
    
    def detect(self):
        """
        Detect web technologies used by the domain
        """
        try:
            # Try HTTPS first
            response = self._make_request('https')
            if not response:
                # Fallback to HTTP
                response = self._make_request('http')
            
            if not response:
                return {'error': 'Could not connect to the domain'}
            
            self.headers = dict(response.headers)
            self.html = response.text
            
            # Detect technologies
            self._detect_from_headers()
            self._detect_from_html()
            self._detect_from_meta()
            
            return list(self.technologies)
            
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
    
    def _detect_from_headers(self):
        """
        Detect technologies from HTTP headers
        """
        # Server header
        server = self.headers.get('Server', '').lower()
        if server:
            self.technologies.add(f'Server: {server}')
        
        # X-Powered-By header
        powered_by = self.headers.get('X-Powered-By', '').lower()
        if powered_by:
            self.technologies.add(f'Powered By: {powered_by}')
        
        # Framework detection from headers
        if 'x-aspnet-version' in self.headers:
            self.technologies.add('ASP.NET')
        if 'x-aspnetmvc-version' in self.headers:
            self.technologies.add('ASP.NET MVC')
        if 'x-drupal-cache' in self.headers:
            self.technologies.add('Drupal')
        if 'x-shopify-stage' in self.headers:
            self.technologies.add('Shopify')
        if 'x-generator' in self.headers:
            generator = self.headers['x-generator'].lower()
            if 'wordpress' in generator:
                self.technologies.add('WordPress')
            elif 'drupal' in generator:
                self.technologies.add('Drupal')
    
    def _detect_from_html(self):
        """
        Detect technologies from HTML content
        """
        try:
            soup = BeautifulSoup(self.html, 'html.parser')
            
            # Check meta tags
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and meta_generator.get('content'):
                self.technologies.add(f'Generator: {meta_generator["content"]}')
            
            # Check for common frameworks
            if soup.find('script', src=lambda x: x and 'wp-' in x):
                self.technologies.add('WordPress')
            if soup.find('script', src=lambda x: x and 'drupal' in x):
                self.technologies.add('Drupal')
            if soup.find('script', src=lambda x: x and 'jquery' in x):
                self.technologies.add('jQuery')
            if soup.find('script', src=lambda x: x and 'react' in x):
                self.technologies.add('React')
            if soup.find('script', src=lambda x: x and 'angular' in x):
                self.technologies.add('Angular')
            if soup.find('script', src=lambda x: x and 'vue' in x):
                self.technologies.add('Vue.js')
            
            # Check for common analytics
            if soup.find('script', src=lambda x: x and 'google-analytics' in x):
                self.technologies.add('Google Analytics')
            if soup.find('script', src=lambda x: x and 'hotjar' in x):
                self.technologies.add('Hotjar')
            if soup.find('script', src=lambda x: x and 'mixpanel' in x):
                self.technologies.add('Mixpanel')
            
            # Check for common CDNs
            if soup.find('script', src=lambda x: x and 'cloudflare' in x):
                self.technologies.add('Cloudflare')
            if soup.find('script', src=lambda x: x and 'cloudfront' in x):
                self.technologies.add('Amazon CloudFront')
            
        except Exception as e:
            print(f"Error parsing HTML: {str(e)}")
    
    def _detect_from_meta(self):
        """
        Detect technologies from meta tags
        """
        try:
            soup = BeautifulSoup(self.html, 'html.parser')
            
            # Check viewport meta tag for responsive design
            viewport = soup.find('meta', attrs={'name': 'viewport'})
            if viewport:
                self.technologies.add('Responsive Design')
            
            # Check for common CMS meta tags
            if soup.find('meta', attrs={'name': 'generator', 'content': lambda x: x and 'wordpress' in x.lower()}):
                self.technologies.add('WordPress')
            if soup.find('meta', attrs={'name': 'generator', 'content': lambda x: x and 'drupal' in x.lower()}):
                self.technologies.add('Drupal')
            if soup.find('meta', attrs={'name': 'generator', 'content': lambda x: x and 'joomla' in x.lower()}):
                self.technologies.add('Joomla')
            
        except Exception as e:
            print(f"Error checking meta tags: {str(e)}") 