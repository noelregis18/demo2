import pandas as pd
import json
import os
from datetime import datetime
from app import socketio
from .subdomain_enum import SubdomainEnumerator
from .dns_analyzer import DNSAnalyzer
from .port_scanner import PortScanner
from .ssl_analyzer import SSLAnalyzer
from .header_analyzer import HeaderAnalyzer
from .tech_stack import TechStackDetector
from .risk_analyzer import RiskAnalyzer

class ASMScanner:
    def __init__(self, input_file):
        self.input_file = input_file
        self.output_dir = os.path.dirname(input_file)
        self.domains = []
        self.results = {}
        self.status = {
            'total': 0,
            'completed': 0,
            'current_domain': '',
            'status': 'initialized'
        }
    
    def load_domains(self):
        df = pd.read_csv(self.input_file)
        self.domains = df['domain'].tolist()
        self.status['total'] = len(self.domains)
        self._update_status()
    
    def _update_status(self):
        status_file = os.path.join(self.output_dir, 'scan_status.json')
        with open(status_file, 'w') as f:
            json.dump(self.status, f)
        socketio.emit('status_update', self.status)
    
    def scan_domains(self):
        self.load_domains()
        self.status['status'] = 'scanning'
        self._update_status()
        
        for domain in self.domains:
            self.status['current_domain'] = domain
            self._update_status()
            
            result = {
                'domain': domain,
                'scan_date': datetime.now().isoformat(),
                'subdomains': [],
                'dns_records': {},
                'open_ports': [],
                'tech_stack': [],
                'headers': {},
                'ssl_info': {},
                'osint_findings': [],
                'sensitive_paths': []
            }
            
            # Perform all scans
            try:
                # Subdomain enumeration
                subdomain_enum = SubdomainEnumerator(domain)
                result['subdomains'] = subdomain_enum.enumerate()
                
                # DNS analysis
                dns_analyzer = DNSAnalyzer(domain)
                result['dns_records'] = dns_analyzer.analyze()
                
                # Port scanning
                port_scanner = PortScanner(domain)
                result['open_ports'] = port_scanner.scan()
                
                # SSL analysis
                ssl_analyzer = SSLAnalyzer(domain)
                result['ssl_info'] = ssl_analyzer.analyze()
                
                # Header analysis
                header_analyzer = HeaderAnalyzer(domain)
                result['headers'] = header_analyzer.analyze()
                
                # Technology stack detection
                tech_detector = TechStackDetector(domain)
                result['tech_stack'] = tech_detector.detect()
                
                # Risk analysis
                risk_analyzer = RiskAnalyzer(result)
                risk_score, risk_summary = risk_analyzer.analyze()
                result['risk_score'] = risk_score
                result['risk_summary'] = risk_summary
                
            except Exception as e:
                result['error'] = str(e)
            
            self.results[domain] = result
            self.status['completed'] += 1
            self._update_status()
            
            # Save results after each domain
            self._save_results()
        
        self.status['status'] = 'completed'
        self._update_status()
    
    def _save_results(self):
        results_file = os.path.join(self.output_dir, 'scan_results.json')
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2) 