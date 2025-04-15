import os
import openai
from datetime import datetime

class RiskAnalyzer:
    def __init__(self, scan_results):
        self.scan_results = scan_results
        self.risk_score = 0
        self.risk_summary = ""
        
        # Initialize OpenAI client
        openai.api_key = os.getenv('OPENAI_API_KEY')
    
    def analyze(self):
        """
        Analyze scan results and generate risk score and summary
        """
        try:
            # Calculate base risk score
            self._calculate_base_score()
            
            # Generate AI-powered risk analysis
            self._generate_ai_analysis()
            
            return self.risk_score, self.risk_summary
            
        except Exception as e:
            return 0, f"Error analyzing risks: {str(e)}"
    
    def _calculate_base_score(self):
        """
        Calculate base risk score from scan results
        """
        score = 100
        issues = []
        
        # Check SSL/TLS configuration
        if 'ssl_info' in self.scan_results:
            ssl_info = self.scan_results['ssl_info']
            if isinstance(ssl_info, dict):
                # Check for SSL vulnerabilities
                if 'vulnerabilities' in ssl_info:
                    vulns = ssl_info['vulnerabilities']
                    if vulns.get('heartbleed'):
                        score -= 20
                        issues.append("Critical: Heartbleed vulnerability detected")
                    if vulns.get('poodle'):
                        score -= 15
                        issues.append("High: POODLE vulnerability detected")
                    if vulns.get('beast'):
                        score -= 10
                        issues.append("Medium: BEAST vulnerability detected")
                
                # Check SSL protocols
                if 'protocols' in ssl_info:
                    protocols = ssl_info['protocols']
                    if protocols.get('SSLv2') or protocols.get('SSLv3'):
                        score -= 15
                        issues.append("High: Outdated SSL protocols in use")
        
        # Check security headers
        if 'headers' in self.scan_results:
            headers = self.scan_results['headers']
            if isinstance(headers, dict):
                if not headers.get('Strict-Transport-Security'):
                    score -= 10
                    issues.append("Medium: Missing HSTS header")
                if not headers.get('X-Frame-Options'):
                    score -= 5
                    issues.append("Low: Missing X-Frame-Options header")
                if not headers.get('X-Content-Type-Options'):
                    score -= 5
                    issues.append("Low: Missing X-Content-Type-Options header")
        
        # Check open ports
        if 'open_ports' in self.scan_results:
            open_ports = self.scan_results['open_ports']
            if isinstance(open_ports, list):
                risky_ports = {21, 23, 3389}  # FTP, Telnet, RDP
                for port_info in open_ports:
                    if isinstance(port_info, dict) and port_info.get('port') in risky_ports:
                        score -= 10
                        issues.append(f"High: Risky port {port_info['port']} is open")
        
        # Ensure score stays within bounds
        self.risk_score = max(0, min(100, score))
        self.initial_issues = issues
    
    def _generate_ai_analysis(self):
        """
        Generate AI-powered risk analysis using OpenAI
        """
        try:
            # Prepare the prompt
            prompt = self._prepare_analysis_prompt()
            
            # Call OpenAI API
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing domain security scan results."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.7
            )
            
            # Extract the analysis
            if response.choices and response.choices[0].message:
                self.risk_summary = response.choices[0].message.content.strip()
            else:
                self.risk_summary = "AI analysis unavailable. Using base analysis:\n" + "\n".join(self.initial_issues)
                
        except Exception as e:
            self.risk_summary = f"AI analysis failed. Using base analysis:\n" + "\n".join(self.initial_issues)
    
    def _prepare_analysis_prompt(self):
        """
        Prepare the prompt for AI analysis
        """
        prompt = f"""
        Analyze the following security scan results for {self.scan_results['domain']} and provide a concise risk assessment:
        
        Risk Score: {self.risk_score}
        
        Initial Issues:
        {chr(10).join(self.initial_issues)}
        
        Scan Details:
        1. SSL/TLS Configuration: {self.scan_results.get('ssl_info', {})}
        2. Security Headers: {self.scan_results.get('headers', {})}
        3. Open Ports: {self.scan_results.get('open_ports', [])}
        4. Technology Stack: {self.scan_results.get('tech_stack', [])}
        
        Please provide:
        1. A brief summary of the most critical security risks
        2. The potential impact of these vulnerabilities
        3. Prioritized recommendations for remediation
        
        Format the response in clear, concise bullet points.
        """
        
        return prompt 