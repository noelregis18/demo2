import subprocess
import requests
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

class SubdomainEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
    
    def enumerate(self):
        """
        Enumerate subdomains using multiple methods
        """
        # Use multiple enumeration methods in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self._amass_enum),
                executor.submit(self._subfinder_enum),
                executor.submit(self._certificate_transparency)
            ]
            
            for future in futures:
                try:
                    subdomains = future.result()
                    self.subdomains.update(subdomains)
                except Exception as e:
                    print(f"Error in subdomain enumeration: {str(e)}")
        
        # Validate subdomains
        valid_subdomains = self._validate_subdomains()
        
        return {
            'total_found': len(self.subdomains),
            'valid': len(valid_subdomains),
            'subdomains': list(valid_subdomains)
        }
    
    def _amass_enum(self):
        """
        Use Amass for subdomain enumeration
        """
        try:
            cmd = f"amass enum -d {self.domain} -passive"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            return set(result.stdout.splitlines())
        except Exception as e:
            print(f"Amass enumeration error: {str(e)}")
            return set()
    
    def _subfinder_enum(self):
        """
        Use Subfinder for subdomain enumeration
        """
        try:
            cmd = f"subfinder -d {self.domain} -silent"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            return set(result.stdout.splitlines())
        except Exception as e:
            print(f"Subfinder enumeration error: {str(e)}")
            return set()
    
    def _certificate_transparency(self):
        """
        Query certificate transparency logs
        """
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                return set(entry['name_value'].lower() for entry in data)
            return set()
        except Exception as e:
            print(f"Certificate transparency query error: {str(e)}")
            return set()
    
    def _validate_subdomains(self):
        """
        Validate discovered subdomains
        """
        valid_subdomains = set()
        
        def check_subdomain(subdomain):
            try:
                # Try HTTP
                url = f"http://{subdomain}"
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code < 400:
                    return subdomain
                
                # Try HTTPS
                url = f"https://{subdomain}"
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code < 400:
                    return subdomain
                
                return None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_subdomain, subdomain) for subdomain in self.subdomains]
            for future in futures:
                result = future.result()
                if result:
                    valid_subdomains.add(result)
        
        return valid_subdomains 