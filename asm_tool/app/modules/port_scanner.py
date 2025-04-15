import nmap
import socket
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self, domain):
        self.domain = domain
        self.nm = nmap.PortScanner()
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080
        ]
    
    def scan(self):
        """
        Perform port scan on the domain
        """
        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(self.domain)
            
            # Scan common ports first
            common_results = self._scan_ports(ip, self.common_ports)
            
            # If common ports are open, perform a full scan
            if any(port['state'] == 'open' for port in common_results):
                full_results = self._full_scan(ip)
                return full_results
            
            return common_results
            
        except Exception as e:
            return [{'error': str(e)}]
    
    def _scan_ports(self, ip, ports):
        """
        Scan specific ports
        """
        try:
            # Convert ports list to string
            port_str = ','.join(map(str, ports))
            
            # Perform the scan
            self.nm.scan(ip, port_str, arguments='-sV -T4')
            
            results = []
            for port in ports:
                port_info = {
                    'port': port,
                    'state': 'closed',
                    'service': 'unknown',
                    'version': ''
                }
                
                if ip in self.nm.all_hosts():
                    if str(port) in self.nm[ip]['tcp']:
                        port_data = self.nm[ip]['tcp'][str(port)]
                        port_info.update({
                            'state': port_data['state'],
                            'service': port_data['name'],
                            'version': port_data.get('version', '')
                        })
                
                results.append(port_info)
            
            return results
            
        except Exception as e:
            return [{'error': str(e)}]
    
    def _full_scan(self, ip):
        """
        Perform a full port scan
        """
        try:
            # Perform a full scan with service detection
            self.nm.scan(ip, arguments='-sV -T4 -p-')
            
            results = []
            if ip in self.nm.all_hosts():
                for port in self.nm[ip]['tcp']:
                    port_data = self.nm[ip]['tcp'][port]
                    if port_data['state'] == 'open':
                        results.append({
                            'port': port,
                            'state': port_data['state'],
                            'service': port_data['name'],
                            'version': port_data.get('version', '')
                        })
            
            return results
            
        except Exception as e:
            return [{'error': str(e)}]
    
    def _is_port_open(self, ip, port):
        """
        Quick check if a port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False 