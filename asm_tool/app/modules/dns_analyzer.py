import dns.resolver
import whois
from datetime import datetime

class DNSAnalyzer:
    def __init__(self, domain):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def analyze(self):
        """
        Analyze DNS records and WHOIS information
        """
        result = {
            'whois': self._get_whois_info(),
            'a_records': self._get_records('A'),
            'aaaa_records': self._get_records('AAAA'),
            'mx_records': self._get_records('MX'),
            'ns_records': self._get_records('NS'),
            'txt_records': self._get_records('TXT'),
            'spf_record': self._get_spf_record(),
            'dmarc_record': self._get_dmarc_record()
        }
        
        return result
    
    def _get_whois_info(self):
        """
        Get WHOIS information for the domain
        """
        try:
            w = whois.whois(self.domain)
            return {
                'registrar': w.registrar,
                'creation_date': w.creation_date.isoformat() if isinstance(w.creation_date, datetime) else None,
                'expiration_date': w.expiration_date.isoformat() if isinstance(w.expiration_date, datetime) else None,
                'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else []
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_records(self, record_type):
        """
        Get DNS records of specified type
        """
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            return [str(rdata) for rdata in answers]
        except Exception:
            return []
    
    def _get_spf_record(self):
        """
        Get SPF record from TXT records
        """
        try:
            txt_records = self._get_records('TXT')
            for record in txt_records:
                if record.startswith('v=spf1'):
                    return record
            return None
        except Exception:
            return None
    
    def _get_dmarc_record(self):
        """
        Get DMARC record
        """
        try:
            dmarc_domain = f'_dmarc.{self.domain}'
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                if str(rdata).startswith('v=DMARC1'):
                    return str(rdata)
            return None
        except Exception:
            return None 