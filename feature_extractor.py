import re
import urllib.parse
from tld import get_tld
import socket

class URLFeatureExtractor:
    """
    Extracts various features from URLs for phishing detection.
    """
    
    def __init__(self):
        # Common phishing keywords
        self.phishing_keywords = [
            'secure', 'account', 'update', 'confirm', 'login', 'signin',
            'bank', 'verify', 'suspend', 'click', 'here', 'urgent',
            'paypal', 'ebay', 'amazon', 'microsoft', 'apple', 'google'
        ]
        
        # Common legitimate TLDs
        self.legitimate_tlds = [
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int'
        ]
    
    def extract_features(self, url):
        """
        Extract comprehensive features from a URL.
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Dictionary containing extracted features
        """
        features = {}
        
        # Basic URL properties
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questions'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_ands'] = url.count('&')
        features['num_percent'] = url.count('%')
        
        # Special characters count
        special_chars = re.findall(r'[^a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=]', url)
        features['num_special_chars'] = len(special_chars)
        
        # Protocol features
        features['https'] = 1 if url.startswith('https://') else 0
        features['http'] = 1 if url.startswith('http://') else 0
        
        # IP address detection
        features['has_ip'] = self._has_ip_address(url)
        
        # Domain features
        domain_features = self._extract_domain_features(url)
        features.update(domain_features)
        
        # Path features
        path_features = self._extract_path_features(url)
        features.update(path_features)
        
        # Query features
        query_features = self._extract_query_features(url)
        features.update(query_features)
        
        # Suspicious patterns
        suspicious_features = self._extract_suspicious_patterns(url)
        features.update(suspicious_features)
        
        # Phishing keywords
        features['num_phishing_keywords'] = self._count_phishing_keywords(url)
        
        return features
    
    def _has_ip_address(self, url):
        """Check if URL contains an IP address instead of domain name."""
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            if hostname:
                # Check for IPv4
                ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
                if re.match(ipv4_pattern, hostname):
                    return 1
                # Check for IPv6
                try:
                    socket.inet_pton(socket.AF_INET6, hostname)
                    return 1
                except socket.error:
                    pass
            return 0
        except:
            return 0
    
    def _extract_domain_features(self, url):
        """Extract domain-related features."""
        features = {}
        
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ''
            
            # Domain length
            features['domain_length'] = len(hostname)
            
            # Number of subdomains
            subdomains = hostname.split('.')
            features['num_subdomains'] = len(subdomains) - 2 if len(subdomains) > 2 else 0
            
            # TLD features
            try:
                tld_info = get_tld(url, as_object=True)
                tld = tld_info.tld
                features['tld_length'] = len(tld)
                features['legitimate_tld'] = 1 if tld in self.legitimate_tlds else 0
            except:
                features['tld_length'] = 0
                features['legitimate_tld'] = 0
            
            # Domain contains digits
            features['domain_has_digits'] = 1 if re.search(r'\d', hostname) else 0
            
            # Domain contains hyphens
            features['domain_has_hyphens'] = 1 if '-' in hostname else 0
            
        except:
            features['domain_length'] = 0
            features['num_subdomains'] = 0
            features['tld_length'] = 0
            features['legitimate_tld'] = 0
            features['domain_has_digits'] = 0
            features['domain_has_hyphens'] = 0
        
        return features
    
    def _extract_path_features(self, url):
        """Extract path-related features."""
        features = {}
        
        try:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path
            
            # Path length
            features['path_length'] = len(path)
            
            # Number of path segments
            segments = [seg for seg in path.split('/') if seg]
            features['num_path_segments'] = len(segments)
            
            # Path contains suspicious patterns
            features['path_has_exe'] = 1 if '.exe' in path.lower() else 0
            features['path_has_zip'] = 1 if '.zip' in path.lower() else 0
            
        except:
            features['path_length'] = 0
            features['num_path_segments'] = 0
            features['path_has_exe'] = 0
            features['path_has_zip'] = 0
        
        return features
    
    def _extract_query_features(self, url):
        """Extract query string features."""
        features = {}
        
        try:
            parsed = urllib.parse.urlparse(url)
            query = parsed.query
            
            # Query length
            features['query_length'] = len(query)
            
            # Number of query parameters
            if query:
                params = query.split('&')
                features['num_query_params'] = len(params)
            else:
                features['num_query_params'] = 0
            
        except:
            features['query_length'] = 0
            features['num_query_params'] = 0
        
        return features
    
    def _extract_suspicious_patterns(self, url):
        """Extract suspicious pattern features."""
        features = {}
        
        # Double slashes in path
        features['has_double_slash'] = 1 if '//' in url[8:] else 0
        
        # URL shorteners
        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
            'ow.ly', 'is.gd', 'buff.ly', 'adf.ly'
        ]
        features['is_shortened'] = 1 if any(shortener in url for shortener in shorteners) else 0
        
        # Suspicious file extensions
        suspicious_extensions = ['.exe', '.scr', '.bat', '.com', '.pif', '.vbs']
        features['has_suspicious_extension'] = 1 if any(ext in url.lower() for ext in suspicious_extensions) else 0
        
        # Redirect patterns
        features['has_redirect'] = 1 if re.search(r'redirect|redir|r\.php|go\.php|link\.php', url.lower()) else 0
        
        # Homograph attack (mixed scripts)
        features['has_homograph'] = 1 if self._has_homograph_attack(url) else 0
        
        return features
    
    def _has_homograph_attack(self, url):
        """Detect potential homograph attacks."""
        # Simple check for mixed scripts that could indicate homograph attacks
        latin_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
        url_chars = set(url)
        non_latin_chars = url_chars - latin_chars - set('/:.-_?=&%#@!$(),;~+[]{}|\\')
        
        return len(non_latin_chars) > 0
    
    def _count_phishing_keywords(self, url):
        """Count phishing-related keywords in the URL."""
        url_lower = url.lower()
        count = 0
        for keyword in self.phishing_keywords:
            count += url_lower.count(keyword)
        return count
