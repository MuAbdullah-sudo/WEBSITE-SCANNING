from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from urllib.parse import urlparse
import requests
import ssl
import socket
import json
from datetime import datetime
import io
import time
import re
import urllib3
import dns.resolver
import whois
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app, origins="*")

# ==================== CORE FUNCTIONS (unchanged, but kept) ====================
def get_html_content(url):
    try:
        session = requests.Session()
        response = session.get(
            url, timeout=15, verify=False, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        return {
            'content': response.text,
            'headers': response.headers,
            'final_url': response.url,
            'status_code': response.status_code,
            'history': [r.url for r in response.history]
        }
    except Exception as e:
        return {'error': str(e), 'content': '', 'headers': {}, 'final_url': url}

def check_ssl_certificate(domain):
    result = {
        'valid': False,
        'issuer': None,
        'subject': None,
        'valid_from': None,
        'valid_to': None,
        'days_remaining': 0,
        'protocol': None,
        'cipher': None,
        'supports_tls13': False,
        'weak_cipher': False,
        'self_signed': False,
        'errors': []
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result['valid'] = True
                result['protocol'] = ssock.version()
                result['cipher'] = ssock.cipher()[0]
                if any(weak in result['cipher'] for weak in ['RC4', 'DES', 'NULL', 'MD5']):
                    result['weak_cipher'] = True
                issuer = dict(x[0] for x in cert['issuer'])
                result['issuer'] = issuer.get('organizationName', ['Unknown'])[0]
                subject = dict(x[0] for x in cert['subject'])
                result['subject'] = subject.get('commonName', domain)
                result['valid_from'] = cert.get('notBefore', 'Unknown')
                result['valid_to'] = cert.get('notAfter', 'Unknown')
                expiry_date = datetime.strptime(result['valid_to'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.now()).days
                result['days_remaining'] = days_left
                if days_left < 0:
                    result['valid'] = False
                    result['errors'].append(f"Certificate expired {abs(days_left)} days ago")
                elif days_left < 30:
                    result['errors'].append(f"Certificate expires in {days_left} days")
                if result['issuer'] == result['subject']:
                    result['self_signed'] = True
                # TLS 1.3 support check (quick)
                result['supports_tls13'] = False
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                    with socket.create_connection((domain, 443), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=domain):
                            result['supports_tls13'] = True
                except:
                    pass
    except Exception as e:
        result['valid'] = False
        result['errors'].append(str(e))
    return result

def check_headers_advanced(url):
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        headers = response.headers
        redirect_chain = [r.url for r in response.history] + [response.url]
        values = {
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
            'Permissions-Policy': headers.get('Permissions-Policy', 'Missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
            'Cache-Control': headers.get('Cache-Control', 'Missing')
        }
        return {
            'status_code': response.status_code,
            'final_url': response.url,
            'redirects_to_https': response.url.startswith('https'),
            'redirect_chain': redirect_chain,
            'server_leak': headers.get('Server', 'Not disclosed'),
            'x_powered_by': headers.get('X-Powered-By', 'Not disclosed'),
            'values': values,
            'error': None
        }
    except Exception as e:
        return {'error': str(e)}

def detect_platform_advanced(url, html_content, headers):
    # Copy your existing detect_website_platform function here (the one from your working code)
    # It should return a dict with 'platforms', 'wordpress', 'shopify', etc.
    # I'll reuse the one from your working code, but I'll rename it to detect_platform_advanced for consistency.
    # To avoid duplication, I'll embed the exact function from your working code.
    platforms = {
        'WordPress': {
            'indicators': [
                '/wp-content/', '/wp-includes/', 'wp-json', 'wordpress',
                'wp-admin', 'wp-login', 'wp-cron', 'wp-embed',
                'generator" content="WordPress', 'wp-', 'WordPress'
            ],
            'score': 0
        },
        'Shopify': {
            'indicators': [
                'cdn.shopify.com', 'myshopify.com', 'shopify-payment',
                'shopify-section', 'shopify-app', 'Shopify.theme'
            ],
            'score': 0
        },
        'Wix': {
            'indicators': ['wix.com', 'wixstatic', 'wix-code', 'wix-', 'Wix'],
            'score': 0
        },
        'Squarespace': {
            'indicators': ['squarespace', 'static.squarespace', 'sqsp'],
            'score': 0
        },
        'Magento': {
            'indicators': ['Magento', 'mage-', 'Mage.Cookies', 'Magefan', 'skin/frontend'],
            'score': 0
        },
        'Joomla': {
            'indicators': ['joomla', 'media/system', 'com_content', 'Joomla!'],
            'score': 0
        },
        'Drupal': {
            'indicators': ['drupal', 'sites/default', 'Drupal.settings', 'drupal.js'],
            'score': 0
        }
    }
    
    html_lower = html_content.lower()
    headers_str = str(headers).lower()
    
    for platform, data in platforms.items():
        score = 0
        for indicator in data['indicators']:
            if indicator.lower() in html_lower or indicator.lower() in headers_str:
                score += 10
        platforms[platform]['score'] = score
    
    detected = [p for p in platforms if platforms[p]['score'] >= 20]
    
    wordpress_details = {}
    if 'WordPress' in detected or '/wp-' in html_lower:
        wordpress_details = analyze_wordpress_deep(url, html_content, headers)
    
    shopify_details = {}
    if 'Shopify' in detected or 'shopify' in html_lower:
        shopify_details = analyze_shopify_deep(url, html_content, headers)
    
    return {
        'platforms': detected if detected else ['Generic/Unknown'],
        'primary_platform': detected[0] if detected else 'Unknown',
        'wordpress': wordpress_details,
        'shopify': shopify_details,
        'server': headers.get('Server', 'Unknown'),
        'powered_by': headers.get('X-Powered-By', 'Unknown')
    }

def analyze_wordpress_deep(url, html, headers):
    # Your existing WordPress deep analysis function
    result = {
        'detected': True,
        'version': None,
        'plugins': [],
        'themes': [],
        'vulnerabilities': [],
        'security_issues': []
    }
    base_url = url.rstrip('/')
    html_lower = html.lower()
    
    # Version detection
    version_patterns = [
        r'wp-content/themes/[^/]+/style\.css\?ver=([0-9.]+)',
        r'wp-includes/js/wp-embed\.min\.js\?ver=([0-9.]+)',
        r'<meta name="generator" content="WordPress ([0-9.]+)"'
    ]
    for pattern in version_patterns:
        match = re.search(pattern, html_lower)
        if match:
            result['version'] = match.group(1)
            break
    
    # Plugins
    plugin_patterns = [
        r'wp-content/plugins/([^/"\']+)/',
        r'/wp-json/wp/v2/plugin',
        r'wp-content/plugins/[^/]+/style\.css'
    ]
    for pattern in plugin_patterns:
        matches = re.findall(pattern, html_lower)
        for match in matches:
            plugin_name = match.replace('/', '').replace('.css', '').strip()
            if plugin_name and len(plugin_name) < 40 and plugin_name not in result['plugins']:
                result['plugins'].append(plugin_name)
    
    # Themes
    theme_patterns = [
        r'wp-content/themes/([^/"\']+)/',
        r'themes/[^/]+/style\.css'
    ]
    for pattern in theme_patterns:
        matches = re.findall(pattern, html_lower)
        for match in matches:
            theme_name = match.replace('/', '').strip()
            if theme_name and theme_name not in result['themes']:
                result['themes'].append(theme_name)
    
    # Security checks (simplified)
    try:
        r = requests.get(f"{base_url}/xmlrpc.php", timeout=3, verify=False)
        if r.status_code == 200:
            result['vulnerabilities'].append({
                'type': 'XML-RPC Enabled',
                'severity': 'Medium',
                'details': 'XML-RPC can be used for DDoS attacks and brute force',
                'fix': 'Disable XML-RPC or restrict access via .htaccess'
            })
    except:
        pass
    try:
        r = requests.get(f"{base_url}/wp-admin", timeout=3, verify=False)
        if r.status_code == 200:
            result['vulnerabilities'].append({
                'type': 'Admin Login Exposed',
                'severity': 'Medium',
                'details': 'WordPress admin login page is publicly accessible',
                'fix': 'Add two-factor authentication or restrict admin access by IP'
            })
    except:
        pass
    return result

def analyze_shopify_deep(url, html, headers):
    result = {
        'detected': True,
        'has_ssl': url.startswith('https'),
        'checkout_secure': None,
        'payment_gateways': [],
        'vulnerabilities': []
    }
    html_lower = html.lower()
    gateways = {
        'PayPal': 'paypal',
        'Stripe': 'stripe',
        'Shopify Payments': 'shopify-payment',
        'Amazon Pay': 'amazon-pay',
        'Apple Pay': 'apple-pay'
    }
    for gateway, indicator in gateways.items():
        if indicator in html_lower:
            result['payment_gateways'].append(gateway)
    if '/checkout' in html_lower:
        result['checkout_secure'] = url.startswith('https')
        if not result['checkout_secure']:
            result['vulnerabilities'].append({
                'type': 'Insecure Checkout',
                'severity': 'Critical',
                'details': 'Checkout page is not using HTTPS',
                'fix': 'Force HTTPS for all checkout pages'
            })
    return result

def analyze_security_headers(headers):
    analysis = {'present': [], 'missing': [], 'recommendations': []}
    critical_headers = {
        'Strict-Transport-Security': 'Enforces HTTPS only connections',
        'Content-Security-Policy': 'Prevents XSS and data injection attacks',
        'X-Frame-Options': 'Prevents clickjacking attacks',
        'X-Content-Type-Options': 'Prevents MIME type sniffing',
        'Referrer-Policy': 'Controls referrer information leakage',
        'Permissions-Policy': 'Controls browser features'
    }
    for header, description in critical_headers.items():
        if headers.get(header):
            analysis['present'].append(header)
        else:
            analysis['missing'].append(header)
            analysis['recommendations'].append(f"Add {header}: {description}")
    return analysis

def scan_vulnerabilities_advanced(url, html_content, headers, platform_info):
    # Your existing vulnerability scanning function (returns list of dicts with 'type','severity','details','fix','title')
    vulnerabilities = []
    base_url = url.rstrip('/')
    sensitive_files = [
        ('.env', 'Critical', 'Environment variables with credentials'),
        ('wp-config.php', 'Critical', 'WordPress database configuration'),
        ('robots.txt', 'Low', 'May expose hidden directories'),
        ('.git/config', 'High', 'Git repository exposed'),
        ('backup.zip', 'High', 'Backup file may contain sensitive data')
    ]
    for file, severity, description in sensitive_files:
        try:
            r = requests.get(f"{base_url}/{file}", timeout=3, verify=False)
            if r.status_code == 200:
                vulnerabilities.append({
                    'type': f'Exposed {file}',
                    'severity': severity,
                    'details': f'{description} is publicly accessible',
                    'fix': f'Remove {file} from web root',
                    'title': f'Exposed {file}'
                })
        except:
            pass
    if url.startswith('https'):
        mixed_patterns = re.findall(r'http://[^"\']+\.(js|css|jpg|png|gif)', html_content)
        if mixed_patterns:
            vulnerabilities.append({
                'type': 'Mixed Content',
                'severity': 'High',
                'details': f'Found {len(mixed_patterns)} HTTP resources on HTTPS page',
                'fix': 'Replace all HTTP URLs with HTTPS',
                'title': 'Mixed Content'
            })
    missing_headers = []
    critical_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
    for h in critical_headers:
        if headers.get(h) == 'Missing':
            missing_headers.append(h)
    if missing_headers:
        vulnerabilities.append({
            'type': 'Missing Security Headers',
            'severity': 'High' if 'Strict-Transport-Security' in missing_headers else 'Medium',
            'details': f'Missing headers: {", ".join(missing_headers)}',
            'fix': 'Add these headers in server configuration',
            'title': 'Missing Security Headers'
        })
    if 'action="http://' in html_content:
        vulnerabilities.append({
            'type': 'Insecure Form Submission',
            'severity': 'High',
            'details': 'Forms submit to HTTP endpoint instead of HTTPS',
            'fix': 'Change form action to HTTPS URL',
            'title': 'Insecure Form Submission'
        })
    return vulnerabilities

def scan_ports(domain):
    port_info = {
        21: {'service': 'FTP', 'dangerous': True, 'risk': 'Credentials sent in plaintext'},
        22: {'service': 'SSH', 'dangerous': False, 'risk': 'Low if properly configured'},
        23: {'service': 'Telnet', 'dangerous': True, 'risk': 'No encryption, credentials exposed'},
        25: {'service': 'SMTP', 'dangerous': False, 'risk': 'Mail server'},
        53: {'service': 'DNS', 'dangerous': False, 'risk': 'DNS server'},
        80: {'service': 'HTTP', 'dangerous': False, 'risk': 'Web traffic (non-SSL)'},
        443: {'service': 'HTTPS', 'dangerous': False, 'risk': 'Secure web traffic'},
        445: {'service': 'SMB', 'dangerous': True, 'risk': 'Ransomware vector (EternalBlue)'},
        3306: {'service': 'MySQL', 'dangerous': True, 'risk': 'Database exposed to internet'},
        5432: {'service': 'PostgreSQL', 'dangerous': True, 'risk': 'Database exposed to internet'},
        27017: {'service': 'MongoDB', 'dangerous': True, 'risk': 'No-auth database exposure'},
        6379: {'service': 'Redis', 'dangerous': True, 'risk': 'No-auth cache exposure'},
        8080: {'service': 'HTTP-Alt', 'dangerous': False, 'risk': 'Alternative HTTP port'},
        8443: {'service': 'HTTPS-Alt', 'dangerous': False, 'risk': 'Alternative HTTPS port'}
    }
    open_ports = []
    for port, info in port_info.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append({
                    'port': port,
                    'service': info['service'],
                    'dangerous': info['dangerous'],
                    'risk': info['risk']
                })
            sock.close()
        except:
            pass
    return open_ports

def calculate_improved_score(ssl_result, vulnerabilities, headers_analysis, open_ports, dns_sec):
    score = 100
    # SSL
    if ssl_result.get('valid'):
        if ssl_result.get('days_remaining', 0) < 30:
            score -= 15
        elif ssl_result.get('days_remaining', 0) < 7:
            score -= 25
    else:
        score -= 35
    # Vulnerabilities
    for v in vulnerabilities:
        if v['severity'] == 'Critical':
            score -= 20
        elif v['severity'] == 'High':
            score -= 12
        elif v['severity'] == 'Medium':
            score -= 6
        elif v['severity'] == 'Low':
            score -= 3
    # Security headers
    missing_count = len(headers_analysis.get('missing', []))
    score -= missing_count * 3
    if 'Strict-Transport-Security' in headers_analysis.get('missing', []):
        score -= 5
    if 'Content-Security-Policy' in headers_analysis.get('missing', []):
        score -= 5
    # Open ports
    dangerous_ports = len([p for p in open_ports if p.get('dangerous')])
    score -= dangerous_ports * 5
    # DNS
    if not dns_sec.get('spf'):
        score -= 5
    if not dns_sec.get('dmarc'):
        score -= 5
    return max(0, min(100, score))

def get_professional_grade(score):
    if score >= 90:
        return 'A+', 'Excellent', 'Your website demonstrates exceptional security practices.'
    elif score >= 80:
        return 'A', 'Great', 'Strong security posture with minor improvements needed.'
    elif score >= 70:
        return 'B+', 'Good', 'Solid security but several areas need attention.'
    elif score >= 60:
        return 'B', 'Fair', 'Security is adequate but requires improvement in key areas.'
    elif score >= 50:
        return 'C', 'Needs Improvement', 'Multiple security weaknesses detected.'
    elif score >= 40:
        return 'D', 'Poor', 'Significant security vulnerabilities present.'
    else:
        return 'F', 'Critical', 'Immediate security action required!'

# ==================== NEW ENHANCEMENTS (compatible with frontend) ====================
def dns_security_check(domain):
    result = {'spf': None, 'dmarc': None, 'mx_records': [], 'caa': []}
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        result['mx_records'] = [str(r.exchange) for r in mx]
    except:
        pass
    try:
        txt = dns.resolver.resolve(domain, 'TXT')
        for r in txt:
            if 'v=spf1' in str(r):
                result['spf'] = str(r)
                break
    except:
        pass
    try:
        dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        result['dmarc'] = str(dmarc[0])
    except:
        pass
    return result

def subdomain_enumeration(domain):
    common = ['www', 'mail', 'ftp', 'blog', 'api', 'admin', 'dev', 'test',
              'staging', 'shop', 'store', 'cpanel', 'webmail', 'm', 'secure']
    found = []
    for sub in common:
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            status = None
            try:
                r = requests.get(f"http://{sub}.{domain}", timeout=3, verify=False)
                status = r.status_code
            except:
                status = 0
            found.append({
                'subdomain': f"{sub}.{domain}",
                'ip': ip,
                'status': status,
                'dangerous': False
            })
        except:
            pass
    return found

def performance_analysis(url, html, headers, start_time):
    load_time = (time.time() - start_time) * 1000
    page_size = len(html)
    compression = 'gzip' in headers.get('Content-Encoding', '')
    redirects = len(headers.get('redirect_chain', [])) if 'redirect_chain' in headers else 0
    https_enforced = url.startswith('https') and headers.get('redirects_to_https', False)
    if load_time < 1000:
        speed_rating = 'Excellent'
    elif load_time < 3000:
        speed_rating = 'Good'
    elif load_time < 6000:
        speed_rating = 'Average'
    else:
        speed_rating = 'Poor'
    return {
        'load_time_ms': round(load_time, 0),
        'page_size_bytes': page_size,
        'speed_rating': speed_rating,
        'redirects': redirects,
        'compression': compression,
        'caching_headers': 'Cache-Control' in headers,
        'image_lazy_loading': 'loading="lazy"' in html,
        'minified_resources': False,
        'https_enforced': https_enforced
    }

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {
            'domain_name': w.domain_name if w.domain_name else domain,
            'registrar': w.registrar if w.registrar else 'Not available',
            'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
            'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
            'updated_date': str(w.updated_date) if w.updated_date else 'Unknown',
            'country': w.country if w.country else 'Unknown',
            'name_servers': w.name_servers if w.name_servers else []
        }
    except:
        return {
            'domain_name': domain,
            'registrar': 'Not retrieved',
            'creation_date': 'Unknown',
            'expiration_date': 'Unknown',
            'updated_date': 'Unknown',
            'country': 'Unknown',
            'name_servers': []
        }

def cookie_audit(headers):
    cookies = []
    set_cookie = headers.get('Set-Cookie', '')
    if set_cookie:
        for cookie in set_cookie.split(','):
            cookie = cookie.strip()
            flags = {
                'HttpOnly': 'HttpOnly' in cookie,
                'Secure': 'Secure' in cookie,
                'SameSite': re.search(r'SameSite=(\w+)', cookie)
            }
            if flags['SameSite']:
                flags['SameSite'] = flags['SameSite'].group(1)
            cookies.append({
                'name': cookie.split('=')[0],
                'flags': flags
            })
    return cookies

def api_endpoint_discovery(html):
    apis = []
    patterns = [
        r'https?://[^"\']*api[^"\']*',
        r'https?://[^"\']*/v\d+[^"\']*',
        r'https?://[^"\']*/graphql[^"\']*'
    ]
    for pattern in patterns:
        matches = re.findall(pattern, html, re.I)
        for m in matches:
            if m not in [a['endpoint'] for a in apis]:
                apis.append({
                    'endpoint': m,
                    'status': 200,
                    'risk': 'unknown'
                })
    return apis[:10]

# ==================== ROUTES ====================
@app.route('/')
def home():
    return jsonify({
        'name': 'ScanMyWeb Professional Security Scanner',
        'version': '3.1',
        'status': 'operational',
        'features': [
            'SSL/TLS Analysis', 'Vulnerability Scanning', 'Platform Detection',
            'Security Headers', 'Port Scanning', 'DNS Security', 'Subdomain Discovery',
            'Performance Metrics', 'Cookie Audit', 'WHOIS Lookup', 'PDF Reports'
        ],
        'endpoints': {
            '/scan': 'GET - Scan a website (use ?url=example.com)',
            '/report': 'GET - Download PDF report'
        }
    })

@app.route('/scan')
def scan_website():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    start_time = time.time()
    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        # Fetch HTML
        html_data = get_html_content(url)
        html = html_data['content']
        headers = html_data['headers']
        final_url = html_data['final_url']

        # Run core scans
        ssl_result = check_ssl_certificate(domain)
        headers_result = check_headers_advanced(url)
        platform_info = detect_platform_advanced(url, html, headers)
        vulnerabilities = scan_vulnerabilities_advanced(url, html, headers, platform_info)
        open_ports = scan_ports(domain)

        # Enhanced scans
        dns_sec = dns_security_check(domain)
        subdomains = subdomain_enumeration(domain)
        perf = performance_analysis(url, html, headers, start_time)
        whois_info = whois_lookup(domain)
        cookies = cookie_audit(headers)
        apis = api_endpoint_discovery(html)

        # Build findings array (for frontend)
        findings = []
        for v in vulnerabilities:
            findings.append({
                'severity': v['severity'].lower(),
                'title': v['title'],
                'description': v['details'],
                'fix': v['fix'],
                'category': 'security'
            })
        # Add SSL finding if invalid
        if not ssl_result.get('valid'):
            findings.append({
                'severity': 'critical',
                'title': 'Invalid SSL Certificate',
                'description': ssl_result.get('errors', ['Certificate invalid'])[0],
                'fix': 'Install a valid SSL certificate from a trusted CA',
                'category': 'ssl'
            })
        # Add header findings
        for h in ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']:
            if headers.get(h) == 'Missing':
                findings.append({
                    'severity': 'high',
                    'title': f'Missing {h} Header',
                    'description': f'Your website does not set the {h} security header',
                    'fix': f'Add {h} header in your server configuration',
                    'category': 'headers'
                })

        findings_count = {
            'critical': len([f for f in findings if f['severity'] == 'critical']),
            'high': len([f for f in findings if f['severity'] == 'high']),
            'medium': len([f for f in findings if f['severity'] == 'medium']),
            'low': len([f for f in findings if f['severity'] == 'low']),
            'total': len(findings)
        }

        # Calculate score
        score = calculate_improved_score(ssl_result, vulnerabilities, analyze_security_headers(headers), open_ports, dns_sec)
        grade, grade_label, grade_description = get_professional_grade(score)

        # Build results object exactly as frontend expects
        results = {
            'ssl': ssl_result,
            'headers': headers_result,
            'ports': open_ports,
            'technology': {
                'cms': platform_info.get('primary_platform', 'Unknown'),
                'ecommerce': 'Shopify' if 'Shopify' in platform_info.get('platforms', []) else 'None',
                'server': platform_info.get('server', 'Unknown'),
                'cdn': 'Cloudflare' if 'cloudflare' in html.lower() else 'Unknown',
                'frameworks': [],
                'analytics': [],
                'payment_gateways': [],
                'chat_widgets': []
            },
            'performance': perf,
            'dns_email': dns_sec,
            'wordpress': platform_info.get('wordpress', {}),
            'ecommerce': platform_info.get('shopify', {}),
            'subdomains': subdomains,
            'apis': apis,
            'whois': whois_info,
            'cookie_audit': cookies,
            # Optional extras (frontend may not use them but safe)
            'ssl_deep': {},  # optional
            'headers_grade': analyze_security_headers(headers),  # reuse
            'breach_check': [],  # placeholder
            'cve_matches': []   # placeholder
        }

        final_data = {
            'url': url,
            'final_url': final_url,
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'scan_duration': round((time.time() - start_time) * 1000, 0),
            'security_score': score,
            'grade': grade,
            'grade_label': grade_label,
            'grade_description': grade_description,
            'findings': findings,
            'findings_count': findings_count,
            'results': results
        }

        return jsonify(final_data)

    except Exception as e:
        app.logger.error(f"Scan error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/report')
def generate_pdf_report():
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # Get scan results
    try:
        scan_response = requests.get(f"{request.host_url}scan?url={url}")
        data = scan_response.json()
        if 'error' in data:
            return jsonify(data), 400

        # Generate PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#1a4d8c'), spaceAfter=30)
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor('#2c3e50'), spaceAfter=12, spaceBefore=20)
        risk_critical = ParagraphStyle('RiskCritical', parent=styles['Normal'], textColor=colors.HexColor('#c0392b'), fontSize=11)
        risk_high = ParagraphStyle('RiskHigh', parent=styles['Normal'], textColor=colors.HexColor('#e67e22'), fontSize=11)

        # Header
        story.append(Paragraph("Security Scan Report", title_style))
        story.append(Paragraph(f"<b>Domain:</b> {data['domain']}", styles['Normal']))
        story.append(Paragraph(f"<b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))

        # Score
        score = data['security_score']
        grade = data['grade']
        score_color = '#27ae60' if score >= 80 else '#e67e22' if score >= 60 else '#e74c3c'
        score_style = ParagraphStyle('ScoreStyle', parent=styles['Normal'], fontSize=48, textColor=colors.HexColor(score_color), alignment=1)
        story.append(Paragraph(f"<b>Security Score:</b> {score}/100", score_style))
        story.append(Paragraph(f"<b>Grade:</b> {grade} - {data['grade_label']}", styles['Normal']))
        story.append(Paragraph(data['grade_description'], styles['Normal']))
        story.append(Spacer(1, 20))

        # Platform
        story.append(Paragraph("Detected Platform", heading_style))
        tech = data['results']['technology']
        story.append(Paragraph(f"<b>Primary Platform:</b> {tech['cms']}", styles['Normal']))
        story.append(Paragraph(f"<b>Server:</b> {tech['server']}", styles['Normal']))
        story.append(Spacer(1, 12))

        # WordPress details if detected
        wp = data['results'].get('wordpress', {})
        if wp.get('detected'):
            story.append(Paragraph("WordPress Analysis", heading_style))
            if wp.get('version'):
                story.append(Paragraph(f"Version: {wp['version']}", styles['Normal']))
            if wp.get('plugins'):
                story.append(Paragraph(f"Detected Plugins: {', '.join(wp['plugins'][:10])}", styles['Normal']))
            if wp.get('themes'):
                story.append(Paragraph(f"Active Theme: {', '.join(wp['themes'][:3])}", styles['Normal']))
            story.append(Spacer(1, 12))

        # SSL
        story.append(Paragraph("SSL/TLS Certificate", heading_style))
        ssl = data['results']['ssl']
        if ssl.get('valid'):
            story.append(Paragraph("✓ SSL Certificate: Valid", styles['Normal']))
            story.append(Paragraph(f"Issuer: {ssl['issuer']}", styles['Normal']))
            story.append(Paragraph(f"Expires: {ssl['valid_to']}", styles['Normal']))
            story.append(Paragraph(f"Days Remaining: {ssl['days_remaining']}", styles['Normal']))
            story.append(Paragraph(f"Protocol: {ssl['protocol']}", styles['Normal']))
        else:
            story.append(Paragraph(f"✗ SSL Issue: {', '.join(ssl.get('errors', ['Invalid certificate']))}", risk_critical))
        story.append(Spacer(1, 12))

        # Vulnerabilities
        story.append(Paragraph("Vulnerabilities Detected", heading_style))
        vulns = data['findings']
        if vulns:
            for v in vulns:
                if v['severity'] == 'critical':
                    story.append(Paragraph(f"<b>{v['severity'].upper()}:</b> {v['title']}", risk_critical))
                elif v['severity'] == 'high':
                    story.append(Paragraph(f"<b>{v['severity'].upper()}:</b> {v['title']}", risk_high))
                else:
                    story.append(Paragraph(f"<b>{v['severity'].upper()}:</b> {v['title']}", styles['Normal']))
                story.append(Paragraph(f"Details: {v['description']}", styles['Normal']))
                story.append(Paragraph(f"Fix: {v['fix']}", styles['Italic']))
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("✓ No vulnerabilities detected", styles['Normal']))
        story.append(Spacer(1, 12))

        # Security Headers
        story.append(Paragraph("Security Headers Analysis", heading_style))
        headers_analysis = data['results']['headers_grade'] if 'headers_grade' in data['results'] else analyze_security_headers(data['results']['headers'].get('values', {}))
        story.append(Paragraph(f"<b>Present:</b> {', '.join(headers_analysis.get('present', [])) or 'None'}", styles['Normal']))
        story.append(Paragraph(f"<b>Missing:</b> {', '.join(headers_analysis.get('missing', [])) or 'None'}", styles['Normal']))
        story.append(Spacer(1, 12))

        # Open Ports
        story.append(Paragraph("Open Ports Analysis", heading_style))
        ports = data['results']['ports']
        if ports:
            for p in ports:
                risk_text = "⚠ DANGEROUS" if p['dangerous'] else "Open"
                story.append(Paragraph(f"Port {p['port']} ({p['service']}): {risk_text}", styles['Normal']))
                if p.get('dangerous'):
                    story.append(Paragraph(f"Risk: {p['risk']}", styles['Italic']))
        else:
            story.append(Paragraph("✓ No common ports open", styles['Normal']))
        story.append(Spacer(1, 12))

        # DNS Security
        dns = data['results']['dns_email']
        story.append(Paragraph("DNS Security (Email Protection)", heading_style))
        story.append(Paragraph(f"SPF: {'✓ Present' if dns.get('spf') else '✗ Missing'}", styles['Normal']))
        story.append(Paragraph(f"DMARC: {'✓ Present' if dns.get('dmarc') else '✗ Missing'}", styles['Normal']))
        story.append(Paragraph(f"MX Records: {', '.join(dns.get('mx_records', [])) or 'None'}", styles['Normal']))
        story.append(Spacer(1, 12))

        # Subdomains
        subs = data['results']['subdomains']
        if subs:
            story.append(Paragraph("Discovered Subdomains", heading_style))
            for s in subs:
                story.append(Paragraph(f"{s['subdomain']} → {s['ip']} (HTTP {s['status']})", styles['Normal']))
            story.append(Spacer(1, 12))

        # Performance
        perf = data['results']['performance']
        story.append(Paragraph("Performance Analysis", heading_style))
        story.append(Paragraph(f"Load Time: {perf['load_time_ms']} ms", styles['Normal']))
        story.append(Paragraph(f"Page Size: {round(perf['page_size_bytes']/1024, 1)} KB", styles['Normal']))
        story.append(Paragraph(f"Speed Rating: {perf['speed_rating']}", styles['Normal']))
        story.append(Paragraph(f"Redirects: {perf['redirects']}", styles['Normal']))
        story.append(Paragraph(f"Compression: {'Yes' if perf['compression'] else 'No'}", styles['Normal']))
        story.append(Paragraph(f"HTTPS Enforced: {'Yes' if perf['https_enforced'] else 'No'}", styles['Normal']))
        story.append(Spacer(1, 12))

        # WHOIS
        whois_info = data['results']['whois']
        story.append(Paragraph("Domain Registration (WHOIS)", heading_style))
        story.append(Paragraph(f"Registrar: {whois_info['registrar']}", styles['Normal']))
        story.append(Paragraph(f"Created: {whois_info['creation_date']}", styles['Normal']))
        story.append(Paragraph(f"Expires: {whois_info['expiration_date']}", styles['Normal']))
        story.append(Paragraph(f"Name Servers: {', '.join(whois_info['name_servers'][:3]) or 'None'}", styles['Normal']))
        story.append(Spacer(1, 12))

        # Summary Statistics
        story.append(Paragraph("Executive Summary", heading_style))
        stats = data['findings_count']
        story.append(Paragraph(f"Total Vulnerabilities: {stats['total']}", styles['Normal']))
        story.append(Paragraph(f"Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}", styles['Normal']))
        dangerous_ports = len([p for p in ports if p.get('dangerous')])
        story.append(Paragraph(f"Dangerous Open Ports: {dangerous_ports}", styles['Normal']))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"security-report-{data['domain']}.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)