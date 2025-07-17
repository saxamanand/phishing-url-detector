import pandas as pd
import numpy as np
import re
import random
from urllib.parse import urlparse
import string

def generate_sample_data(num_samples=1000):
    """
    Generate sample phishing and legitimate URLs for demonstration.
    Note: In production, use real datasets like PhishTank or similar.
    
    Args:
        num_samples: Number of sample URLs to generate
        
    Returns:
        pd.DataFrame: DataFrame with URLs and labels
    """
    
    # Sample legitimate domains
    legitimate_domains = [
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'twitter.com', 'linkedin.com', 'github.com',
        'stackoverflow.com', 'wikipedia.org', 'youtube.com', 'reddit.com',
        'netflix.com', 'instagram.com', 'paypal.com', 'ebay.com',
        'cnn.com', 'bbc.com', 'nytimes.com', 'washingtonpost.com'
    ]
    
    # Sample phishing patterns
    phishing_patterns = [
        'secure-{domain}',
        '{domain}-verify',
        '{domain}-update',
        'account-{domain}',
        '{domain}-login',
        'confirm-{domain}',
        '{domain}-security',
        'urgent-{domain}',
        '{domain}-suspended',
        '{domain}-alert'
    ]
    
    # Suspicious domains
    suspicious_domains = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
        'phishing-site.com', 'fake-bank.net', 'scam-alert.org'
    ]
    
    # IP addresses for phishing
    ip_addresses = [
        '192.168.1.1', '10.0.0.1', '172.16.0.1',
        '203.0.113.1', '198.51.100.1', '123.45.67.89'
    ]
    
    urls = []
    labels = []
    
    # Generate legitimate URLs
    for _ in range(num_samples // 2):
        domain = random.choice(legitimate_domains)
        
        # Add some variety to legitimate URLs
        if random.random() < 0.3:  # 30% chance of having a path
            path = '/' + '/'.join(random.choices(['about', 'contact', 'services', 'products', 'help'], k=random.randint(1, 3)))
        else:
            path = ''
        
        if random.random() < 0.2:  # 20% chance of having query parameters
            query = '?' + '&'.join([f'{param}={value}' for param, value in 
                                   zip(random.choices(['page', 'id', 'category', 'search'], k=random.randint(1, 2)),
                                       random.choices(['1', 'home', 'news', 'user'], k=random.randint(1, 2)))])
        else:
            query = ''
        
        protocol = 'https://' if random.random() < 0.8 else 'http://'  # 80% https for legitimate
        url = f"{protocol}{domain}{path}{query}"
        
        urls.append(url)
        labels.append(0)  # 0 for legitimate
    
    # Generate phishing URLs
    for _ in range(num_samples // 2):
        phishing_type = random.choice(['suspicious_domain', 'ip_address', 'misleading_pattern'])
        
        if phishing_type == 'suspicious_domain':
            domain = random.choice(suspicious_domains)
            protocol = 'http://' if random.random() < 0.6 else 'https://'  # 60% http for phishing
            
        elif phishing_type == 'ip_address':
            domain = random.choice(ip_addresses)
            protocol = 'http://'
            
        else:  # misleading_pattern
            real_domain = random.choice(legitimate_domains)
            pattern = random.choice(phishing_patterns)
            domain = pattern.format(domain=real_domain.replace('.', '-'))
            domain += random.choice(['.com', '.net', '.org', '.tk', '.ml'])
            protocol = 'http://' if random.random() < 0.7 else 'https://'
        
        # Add suspicious paths and parameters
        if random.random() < 0.5:  # 50% chance of suspicious path
            path = '/' + random.choice(['update', 'verify', 'confirm', 'secure', 'login', 'account'])
        else:
            path = ''
        
        if random.random() < 0.4:  # 40% chance of suspicious query
            query = '?' + '&'.join([f'{param}={value}' for param, value in 
                                   zip(random.choices(['token', 'id', 'redirect', 'confirm'], k=random.randint(1, 3)),
                                       random.choices(['123456', 'true', 'yes', 'now'], k=random.randint(1, 3)))])
        else:
            query = ''
        
        url = f"{protocol}{domain}{path}{query}"
        
        urls.append(url)
        labels.append(1)  # 1 for phishing
    
    # Create DataFrame
    df = pd.DataFrame({
        'url': urls,
        'is_phishing': labels
    })
    
    # Shuffle the data
    df = df.sample(frac=1).reset_index(drop=True)
    
    return df

def validate_url(url):
    """
    Validate if a string is a proper URL.
    
    Args:
        url: String to validate
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def extract_domain(url):
    """
    Extract domain from URL.
    
    Args:
        url: URL string
        
    Returns:
        str: Domain name
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return ""

def is_ip_address(domain):
    """
    Check if domain is an IP address.
    
    Args:
        domain: Domain string
        
    Returns:
        bool: True if IP address, False otherwise
    """
    # IPv4 pattern
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    
    if re.match(ipv4_pattern, domain):
        return True
    
    # Simple IPv6 check
    if ':' in domain and len(domain.split(':')) > 2:
        return True
    
    return False

def clean_url(url):
    """
    Clean and normalize URL for processing.
    
    Args:
        url: Raw URL string
        
    Returns:
        str: Cleaned URL
    """
    url = url.strip()
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    return url

def get_url_statistics(urls):
    """
    Get basic statistics about a list of URLs.
    
    Args:
        urls: List of URLs
        
    Returns:
        dict: Statistics dictionary
    """
    stats = {
        'total_urls': len(urls),
        'avg_length': np.mean([len(url) for url in urls]),
        'max_length': max([len(url) for url in urls]),
        'min_length': min([len(url) for url in urls]),
        'https_count': sum(1 for url in urls if url.startswith('https://')),
        'http_count': sum(1 for url in urls if url.startswith('http://'))
    }
    
    stats['https_percentage'] = (stats['https_count'] / stats['total_urls']) * 100
    stats['http_percentage'] = (stats['http_count'] / stats['total_urls']) * 100
    
    return stats

def format_classification_metrics(accuracy, precision, recall, f1_score):
    """
    Format classification metrics for display.
    
    Args:
        accuracy: Accuracy score
        precision: Precision score
        recall: Recall score
        f1_score: F1 score
        
    Returns:
        str: Formatted metrics string
    """
    return f"""
    Accuracy:  {accuracy:.3f}
    Precision: {precision:.3f}
    Recall:    {recall:.3f}
    F1-Score:  {f1_score:.3f}
    """

def create_feature_description():
    """
    Create a description of all features used in the model.
    
    Returns:
        dict: Feature descriptions
    """
    descriptions = {
        'url_length': 'Total length of the URL',
        'num_dots': 'Number of dots in the URL',
        'num_hyphens': 'Number of hyphens in the URL',
        'num_underscores': 'Number of underscores in the URL',
        'num_slashes': 'Number of slashes in the URL',
        'num_questions': 'Number of question marks in the URL',
        'num_equals': 'Number of equals signs in the URL',
        'num_ands': 'Number of ampersands in the URL',
        'num_percent': 'Number of percent signs in the URL',
        'num_special_chars': 'Number of special characters in the URL',
        'https': 'Whether the URL uses HTTPS protocol',
        'http': 'Whether the URL uses HTTP protocol',
        'has_ip': 'Whether the URL contains an IP address',
        'domain_length': 'Length of the domain name',
        'num_subdomains': 'Number of subdomains',
        'tld_length': 'Length of the top-level domain',
        'legitimate_tld': 'Whether the TLD is commonly legitimate',
        'domain_has_digits': 'Whether the domain contains digits',
        'domain_has_hyphens': 'Whether the domain contains hyphens',
        'path_length': 'Length of the URL path',
        'num_path_segments': 'Number of path segments',
        'path_has_exe': 'Whether the path contains .exe extension',
        'path_has_zip': 'Whether the path contains .zip extension',
        'query_length': 'Length of the query string',
        'num_query_params': 'Number of query parameters',
        'has_double_slash': 'Whether the URL has double slashes in path',
        'is_shortened': 'Whether the URL is from a URL shortener',
        'has_suspicious_extension': 'Whether the URL has suspicious file extensions',
        'has_redirect': 'Whether the URL contains redirect patterns',
        'has_homograph': 'Whether the URL might contain homograph attacks',
        'num_phishing_keywords': 'Number of phishing-related keywords in the URL'
    }
    
    return descriptions
