import re
import urllib
from tldextract import extract
import ssl
import socket
from datetime import datetime
from dateutil import parser
import whois
import favicon
from bs4 import BeautifulSoup
import http.client

TRUSTED_AUTH = ['Comodo', 'Symantec', 'GoDaddy', 'GlobalSign', 'DigiCert', 'StartCom',
                'Entrust', 'Verizon', 'Trustwave', 'Unizeto', 'Buypass', 'QuoVadis', 'Deutsche Telekom',
                'Network Solutions', 'SwissSign', 'IdenTrust', 'Secom', 'TWCA', 'GeoTrust', 'Thawte', 'Doster',
                'VeriSign', 'GTS', 'Sectigo', 'Certum', 'Actalis', "Let's Encrypt", "WISeKey Group",
                "Add Trust", "USERTrust", "Amazon"]

HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '3600',
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
}


def having_ip_address(url):
    # Regex expression for validating IPv4
    ipv4_re = "(([0-9]|[1-9][0-9]|1[0-9][0-9]|"\
        "2[0-4][0-9]|25[0-5])\\.){3}"\
        "([0-9]|[1-9][0-9]|1[0-9][0-9]|"\
        "2[0-4][0-9]|25[0-5])"
    # Regex expression for validating IPv6
    ipv6_re = "((([0-9a-fA-F]){1,4})\\:){7}"\
        "([0-9a-fA-F]){1,4}"
    ip4 = re.compile(ipv4_re)
    ip6 = re.compile(ipv6_re)
    # Checking if has a valid IPv4/IPv6 addresses
    if (re.search(ip4, url) or re.search(ip6, url)):
        return -1  # Phishing
    return 1  # Legitimate


def url_length(url):
    # URL length
    n = len(url)
    if n < 54:
        return 1  # legitimate
    if n >= 54 and n <= 75:
        return 0  # Suspicious
    return -1  # Phishing


def shortining_service(url, resp):
    try:
        if resp.getcode() == 200 and resp.url == url:
            return 1  # legitimate
        return -1  # Phishing
    except Exception as e:
        print(e)
        return -1  # Phishing


def having_at_symbol(url):
    at_symbols = re.findall(r'@', url)
    if len(at_symbols) == 0:
        return 1  # Legitimate
    return -1  # Phishing


def having_double_slash(url):
    index = url.find('//', 7)
    if index == -1:
        return 1  # Legitimate
    return -1  # Phishing


def prefix_suffix(url, domainInfo):
    if domainInfo[1].count('-'):
        return -1  # Phishing
    return 1  # Legitimate


def having_subdomain(url, domainInfo):
    n = domainInfo[0].count('.')
    if n == 0:
        return 1  # Legitimate
    elif n == 1:
        return 0  # Suspicious
    return -1  # Phishing


def ssl_final_state(url, domainInfo, certificate):
    if not re.search('^https', url):
        return -1  # Phishing
    try:
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['commonName'])
        certificate_Auth = certificate_Auth.split()
        if certificate_Auth[0] in ["Network", "Deutsche", "Add", "WISeKey", "Let's"]:
            certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
        else:
            certificate_Auth = certificate_Auth[0]

        # getting age of certificate
        startingDate = parser.parse(str(certificate['notBefore']))
        endingDate = parser.parse(str(certificate['notAfter']))
        age_of_certificate = (endingDate-startingDate).days  # in days
        # mentioned atleast 2 yr but latest update is atmost 1 yr but most of the companies are using 3months (fb, insta, google)
        if (certificate_Auth in TRUSTED_AUTH) and (age_of_certificate >= 80):
            return 1  # legitimate
        elif certificate_Auth not in TRUSTED_AUTH:
            return 0  # Suspicious
        return -1  # Phishing
    except Exception as e:
        print(e)
        return -1


def domain_reg_length(url, domain):
    try:
        updated = domain.updated_date
        if isinstance(updated, list):
            updated = updated[0]
        expiration = domain.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        expiration_of_domain = (expiration - updated).days
        if expiration_of_domain <= 365:
            return -1  # Phishing
        return 1  # Legitimate
    except Exception as e:
        print(e)
        return 0  # Suspicious


def favicon_check(url):
    try:
        fav_url = favicon.get(url)[0].url
        fav_domain_info = extract(fav_url)
        domain_info = extract(url)
        if fav_domain_info[1] != domain_info[1]:
            return -1  # Phishing
        return 1  # Legitimate
    except Exception as e:
        print(e)
        return -1  # Phishing


def port_status(url, domainInfo):
    host_name = domainInfo[1] + "." + domainInfo[2]
    ports = [21, 22, 23, 445, 1433, 1521, 3306, 3389]
    socket_dict = {}
    for port in ports:
        socket_dict[port] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_dict[port].settimeout(2)
    for port in socket_dict:
        try:
            if (socket_dict[port].connect_ex((host_name, port)) == 0):
                return -1  # Phihsing
        except Exception as e:
            print(e)
        socket_dict[port].close()
    return 1  # Legitimate


def check_https_token(url, domain_info):
    host = '.'.join(domain_info)
    if host.count('https'):
        return -1  # Phishing
    return 1  # Legitimate


def request_url(url, domain_info, main_certi, org_name, soup):
    try:
        comb = soup.findAll('img', src=True) + soup.findAll('video',
                                                            src=True) + soup.findAll('audio', src=True)
        total = len(comb)
        belong_to_same = 0
        per = 0
        for item in comb:
            # found in some websites
            item_url = item['src'].replace('https:https:', 'https:')
            item_domain = extract(item_url)
            if item_domain[1] == domain_info[1] or item_domain[1] == '':
                belong_to_same += 1
            elif re.search(r'^https:', item_url):
                certificate = getSSLCertificate(item_domain)
                if not certificate:
                    continue
                if getURLOrganizationName(certificate) == org_name:
                    belong_to_same += 1
        if total != 0:
            per = (total - belong_to_same)/total
        if per < 0.25:
            return 1  # Legitimate
        if per >= 0.25 and per <= 0.61:
            return 0  # Suspicious
        return -1  # Phishing
    except Exception as e:
        print(e)
        return 0  # suspicious


def getURLOrganizationName(certificate):
    if not certificate:
        return None
    issued_to = dict(x[0] for x in certificate['subject'])
    if issued_to and ('organizationName' in issued_to):
        return issued_to['organizationName']
    return None


def getSSLCertificate(domain_info):
    try:
        host_name = '.'.join(
            domain_info) if (domain_info[0] != '' and not domain_info[0].startswith('www')) else domain_info[1] + '.' + domain_info[2]
        context = ssl.create_default_context()
        sct = context.wrap_socket(
            socket.socket(), server_hostname=host_name)
        sct.connect((host_name, 443))
        cert = sct.getpeercert()
        sct.close()
        return cert
    except Exception as e:
        print(e)
        return None


def url_of_anchor(url, domain_info, main_certi, org_name, soup):
    try:
        anchors = soup.findAll('a', href=True)
        total = len(anchors)
        belong_to_same = 0
        per = 0
        for item in anchors:
            item_url = item['href'].replace('https:https:', 'https:')
            item_domain = extract(item_url)
            if item_domain[1] == domain_info[1] or item_domain[1] == '':
                belong_to_same += 1
            elif re.search(r'^https:', item_url):
                certificate = getSSLCertificate(item_domain)
                if not certificate:
                    continue
                if getURLOrganizationName(certificate) == org_name:
                    belong_to_same += 1
        if total != 0:
            per = (total - belong_to_same)/total
        if per < 0.31:
            return 1  # Legitimate
        if per >= 0.31 and per <= 0.67:
            return 0  # Suspicious
        return -1  # Phishing
    except Exception as e:
        print(e)
        return 0  # suspicious


def links_in_tags(url, domain_info, main_certi, org_name, soup):
    try:
        metas = soup.findAll('meta', content=True)
        scripts = soup.findAll('script', src=True)
        links = soup.findAll('link', href=True)
        total = 0
        same_domain = 0
        per = 0
        for meta in metas:
            content = meta.get('content')
            if not content:
                continue
            if content.startswith('https'):
                total += 1
                item_url = content.replace('https:https:', 'https:')
                item_domain = extract(item_url)
                certificate = getSSLCertificate(item_domain)
                if not certificate:
                    continue
                if getURLOrganizationName(certificate) == org_name:
                    same_domain += 1
            elif content.startswith('http'):
                total += 1
        for script in scripts:
            content = script.get('href')
            if not content:
                continue
            if content.startswith('https'):
                total += 1
                item_url = content.replace('https:https:', 'https:')
                item_domain = extract(item_url)
                certificate = getSSLCertificate(item_domain)
                if not certificate:
                    continue
                if getURLOrganizationName(certificate) == org_name:
                    same_domain += 1
            elif content.startswith('http'):
                total += 1
        for link in links:
            content = link.get('href')
            if not content:
                continue
            if content.startswith('https'):
                total += 1
                item_url = content.replace('https:https:', 'https:')
                item_domain = extract(item_url)
                certificate = getSSLCertificate(item_domain)
                if not certificate:
                    continue
                if getURLOrganizationName(certificate) == org_name:
                    same_domain += 1
            elif content.startswith('http'):
                total += 1
        if total != 0:
            per = (total - same_domain)/total
        if per < 0.31:
            return 1  # Legitimate
        if per >= 0.31 and per <= 0.81:
            return 0  # Suspicious
        return -1  # Phishing
    except Exception as e:
        print(e)
        return 0  # Suspicious

# Server Form Handler


def check_sfh(url, domain_info, main_certi, org_name, soup):
    try:
        forms = soup.findAll('form', action=True)
        for item in forms:
            if item['action'] == '' or item['action'] == 'blank':
                return -1  # Phishing
            item_url = item['action'].replace('https:https:', 'https:')
            if item_url.startswith('http:'):
                return 0  # suspicious
            item_domain = extract(item_url)
            if item_domain[1] == domain_info[1] or item_domain[1] == '':
                continue
            elif re.search(r'^https:', item_url):
                certificate = getSSLCertificate(item_domain)
                if not certificate:
                    return 0  # suspicious
                if getURLOrganizationName(certificate) != org_name:
                    return 0  # suspicious
        return 1  # legitimate
    except Exception as e:
        print(e)
        return 0  # suspicious

# Submitting Information to Email


def submitting_to_email(url, soup):
    try:
        if soup.find('mailto:') or soup.find('mail('):
            return -1  # Phishing
        return 1  # legitimate
    except Exception as e:
        print(e)
        return -1  # phishing


def abnormal_URL(url, data):
    try:
        # data = whois.whois(url)
        if data.domain in url:
            return 1  # Legitimate
        return -1  # Phishing
    except Exception as e:
        print(e)
        return -1  # Phishing


def redirect(url):
    return 0


def on_mouseover(url):
    return 0


def on_rightclick(url):
    return 0


def pop_up_window(url):
    return 0


def has_iframe(url, soup):
    try:
        iframes = soup.findAll('iframe')
        if len(iframes):
            return -1  # Phishing
        return 1  # Legitimate
    except Exception as e:
        print(e)
        return -1


def age_of_domain(url, w):
    try:
        start_date = w.creation_date
        if isinstance(start_date, list):
            start_date = start_date[0]
        current_date = datetime.now()
        age = (current_date-start_date).days
        if(age >= 180):
            return 1  # Legitimate
        return -1  # Phishing
    except Exception as e:
        print(e)
        return -1


def dns_record(url, data):
    try:
        if data.domain:
            return 1  # Legitimate
        return -1  # Phishing
    except Exception as e:
        print(e)
        return -1


def web_traffic(url):
    # Alexa URL
    alexa_url = "https://www.alexa.com/siteinfo/"
    domain_info = extract(url)
    search_url = alexa_url + ".".join(domain_info) if domain_info[0] != '' and domain_info[0].startswith(
        'wwww') else alexa_url + domain_info[1] + '.' + domain_info[2]
    try:
        req = urllib.request.Request(
            search_url,
            data=None,
            headers=HEADERS
        )
        opener = urllib.request.urlopen(req).read()
        soup = BeautifulSoup(opener, 'lxml')
        global_rank = soup.select('.rank-global .data')
        match = re.search(r'[\d,]+', global_rank[0].text.strip())
        rank = match.group().replace(',', '')
        if int(rank) < 100000:
            return 1  # Legitimate
        return 0  # suspicious
    except Exception as e:
        print(e)
        return -1  # Phishing

# Google removed its api


def page_rank(url):
    return 0


def google_index(url):
    return 0


def links_pointing_to_page(url):
    return 0


def statistical_report(url):
    return 0


def getFeatures(url):
    req = urllib.request.Request(
        url,
        data=None,
        headers=HEADERS
    )
    resp = urllib.request.urlopen(req)
    opener = resp.read()
    soup = BeautifulSoup(opener, 'lxml')
    domain_info = extract(url)
    domain_whois = whois.whois(url)
    certificate = getSSLCertificate(domain_info)
    org_name = getURLOrganizationName(certificate)
    return [having_ip_address(url),
            url_length(url),
            shortining_service(url, resp),
            having_at_symbol(url),
            having_double_slash(url),
            prefix_suffix(url, domain_info),
            having_subdomain(url, domain_info),
            ssl_final_state(url, domain_info, certificate),
            domain_reg_length(url, domain_whois),
            favicon_check(url),
            port_status(url, domain_info),
            check_https_token(url, domain_info),
            request_url(url, domain_info, certificate, org_name, soup),
            url_of_anchor(url, domain_info, certificate, org_name, soup),
            links_in_tags(url, domain_info, certificate, org_name, soup),
            check_sfh(url, domain_info, certificate, org_name, soup),
            submitting_to_email(url, soup),
            abnormal_URL(url, domain_whois),
            redirect(url),
            on_mouseover(url),
            on_rightclick(url),
            pop_up_window(url),
            has_iframe(url, soup),
            age_of_domain(url, domain_whois),
            dns_record(url, domain_whois),
            web_traffic(url),
            page_rank(url),
            google_index(url),
            links_pointing_to_page(url),
            statistical_report(url)]

