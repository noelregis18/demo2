from flask import Flask, render_template, request, jsonify
import google.generativeai as genai
from dotenv import load_dotenv
import os
import json
from datetime import datetime
import random
import csv

# Load environment variables
load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Configure Gemini API
    genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
    model = genai.GenerativeModel('gemini-1.5-pro')

    @app.route('/')
    def home():
        return render_template('index.html')

    @app.route('/chat', methods=['POST'])
    def chat():
        try:
            data = request.json
            user_message = data.get('message', '')
            
            # Generate response
            response = model.generate_content(user_message)
            
            return jsonify({
                'status': 'success',
                'response': response.text
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/scan', methods=['POST'])
    def scan_domain():
        try:
            data = request.json
            domain = data.get('domain', '')
            
            if not domain:
                return jsonify({
                    'status': 'error',
                    'message': 'Domain is required'
                }), 400
            
            # For demo purposes, we'll generate mock data
            # In a real application, you would perform actual scanning here
            scan_results = generate_mock_scan_results(domain)
            
            # Use Gemini API to analyze results and provide risk summary
            prompt = f"""Analyze this security scan data and provide a concise risk summary (under 100 characters):
            {json.dumps(scan_results, indent=2)}
            """
            
            try:
                ai_response = model.generate_content(prompt)
                scan_results['risk_summary'] = ai_response.text.strip()
            except Exception as e:
                scan_results['risk_summary'] = "Analysis unavailable. Please review raw data."
            
            # Save the results to an output file
            save_scan_results(scan_results)
            
            return jsonify({
                'status': 'success',
                'scan_results': scan_results
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/batch', methods=['POST'])
    def batch_scan():
        try:
            # Check if the post has the file part
            if 'file' not in request.files:
                return jsonify({
                    'status': 'error',
                    'message': 'No file part'
                }), 400
                
            file = request.files['file']
            
            if file.filename == '':
                return jsonify({
                    'status': 'error',
                    'message': 'No selected file'
                }), 400
                
            if file and file.filename.endswith('.csv'):
                # Process the CSV file
                domains = []
                csv_reader = csv.DictReader(file.stream.read().decode('utf-8').splitlines())
                
                for row in csv_reader:
                    if 'domain' in row:
                        domains.append(row['domain'])
                
                if not domains:
                    return jsonify({
                        'status': 'error',
                        'message': 'No domains found in the CSV file'
                    }), 400
                
                results = []
                for domain in domains:
                    scan_results = generate_mock_scan_results(domain)
                    
                    # Use Gemini API to analyze results and provide risk summary
                    prompt = f"""Analyze this security scan data and provide a concise risk summary (under 100 characters):
                    {json.dumps(scan_results, indent=2)}
                    """
                    
                    try:
                        ai_response = model.generate_content(prompt)
                        scan_results['risk_summary'] = ai_response.text.strip()
                    except Exception as e:
                        scan_results['risk_summary'] = "Analysis unavailable. Please review raw data."
                    
                    # Save the results to an output file
                    save_scan_results(scan_results)
                    results.append(scan_results)
                
                return jsonify({
                    'status': 'success',
                    'message': f'Successfully scanned {len(results)} domains',
                    'results': results
                })
            
            return jsonify({
                'status': 'error',
                'message': 'File must be a CSV'
            }), 400
        
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    return app

def generate_mock_scan_results(domain):
    """Generate mock scan results for demonstration purposes."""
    current_date = datetime.now().strftime("%Y-%m-%d")
    
    # Mock subdomains
    subdomains = [
        f"www.{domain}",
        f"mail.{domain}",
        f"api.{domain}",
        f"blog.{domain}",
        f"admin.{domain}"
    ]
    
    # Mock DNS records
    dns_records = {
        "A": [f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"],
        "MX": [f"mail.{domain}", f"alt1.aspmx.l.google.com"],
        "TXT": ["v=spf1 include:_spf.google.com ~all"],
        "NS": [f"ns1.{domain}", f"ns2.{domain}"]
    }
    
    # Mock open ports
    open_ports = [
        {"port": 80, "service": "HTTP", "version": "Apache 2.4.41"},
        {"port": 443, "service": "HTTPS", "version": "Apache 2.4.41"},
        {"port": 22, "service": "SSH", "version": "OpenSSH 7.9"},
        {"port": 25, "service": "SMTP", "version": "Postfix"}
    ]
    
    # Mock technology stack
    tech_stack = [
        "WordPress 5.8.1",
        "PHP 7.4.3",
        "jQuery 3.5.1",
        "Bootstrap 4.5.2",
        "MySQL 5.7.33"
    ]
    
    # Mock HTTP headers
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "X-Frame-Options": "SAMEORIGIN",
        "Content-Type": "text/html; charset=UTF-8",
        "Content-Security-Policy": "missing"
    }
    
    # Mock SSL information
    ssl_info = {
        "certificate_issuer": "Let's Encrypt Authority X3",
        "certificate_subject": f"CN={domain}",
        "certificate_expiry": (datetime.now().replace(month=((datetime.now().month + 2) % 12) or 12)).strftime("%Y-%m-%d"),
        "ssl_version": "TLSv1.2",
        "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
        "has_ssl": True,
        "issues": random.choice([
            ["weak_cipher", "outdated_version"],
            ["self_signed", "common_name_mismatch"],
            []
        ])
    }
    
    # Mock OSINT findings
    osint_findings = [
        {
            "source": "GitHub",
            "finding": "API keys exposed in public repository",
            "url": f"https://github.com/company/{domain}/issues/23"
        },
        {
            "source": "Pastebin",
            "finding": "Database credentials leaked",
            "url": f"https://pastebin.com/abc123def"
        }
    ]
    
    # Mock sensitive paths
    sensitive_paths = [
        {
            "path": "/wp-admin/",
            "status_code": 200,
            "issue": "Admin panel accessible"
        },
        {
            "path": "/.git/",
            "status_code": 403,
            "issue": "Git repository information exposed"
        },
        {
            "path": "/backup/",
            "status_code": 200,
            "issue": "Backup directory accessible"
        }
    ]
    
    # Generate risk score based on findings (higher is more risky)
    vulnerabilities = len(ssl_info["issues"]) + len(sensitive_paths) + len(osint_findings)
    risk_score = min(95, max(10, 30 + (vulnerabilities * 10)))
    
    # Construct the full report
    report = {
        "domain": domain,
        "scan_date": current_date,
        "risk_score": risk_score,
        "risk_summary": "Initial scan complete. AI analysis pending...",
        "subdomains": subdomains,
        "dns_records": dns_records,
        "open_ports": open_ports,
        "tech_stack": tech_stack,
        "headers": headers,
        "ssl_info": ssl_info,
        "osint_findings": osint_findings,
        "sensitive_paths": sensitive_paths
    }
    
    return report

def save_scan_results(scan_results):
    """Save scan results to an output file."""
    # Create outputs directory if it doesn't exist
    outputs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'outputs')
    os.makedirs(outputs_dir, exist_ok=True)
    
    # Create a filename based on the domain and date
    domain = scan_results['domain']
    date = scan_results['scan_date'].replace('-', '')
    filename = f"{domain}_{date}.json"
    file_path = os.path.join(outputs_dir, filename)
    
    # Write the results to the file
    with open(file_path, 'w') as f:
        json.dump(scan_results, f, indent=2)
    
    return file_path 