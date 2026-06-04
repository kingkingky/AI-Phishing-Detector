"""
Advanced Phishing Detection Module
รวมเทคนิคการตรวจจับ phishing สมัยใหม่
"""

import re
import urllib.parse
import tldextract
import whois
import requests
from datetime import datetime, timedelta
from urllib.parse import urlparse
import socket
import ssl
import dns.resolver

class AdvancedPhishingDetector:
    def __init__(self):
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', 
                                '.club', '.online', '.site', '.click', '.loan', 
                                '.download', '.bid', '.party', '.review', '.trade']
        
        self.suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account',
                                    'update', 'confirm', 'banking', 'password', 'credential',
                                    'authenticate', 'validation', 'unlock', 'security']
        
        self.brands = {
            'google': ['googel', 'goole', 'goggle', 'goog1e', 'googlee', 'g00gle', 'go0gle'],
            'facebook': ['facebok', 'faceboook', 'facbook', 'facebookk', 'faceb00k', 'f4cebook'],
            'paypal': ['paypa1', 'paypol', 'paypall', 'papal', 'payp4l', 'p4ypal'],
            'microsoft': ['microsft', 'mcrosoft', 'rnicrosoft', 'mlcrosoft', 'mlcrosoft', 'micr0soft'],
            'amazon': ['amzon', 'amazzon', 'amaz0n', 'amazoon', 'am4zon', '4mazon'],
            'apple': ['app1e', 'appple', 'aple', 'appIe', 'appie'],
            'netflix': ['netflx', 'netfIix', 'netfl1x', 'n3tflix', 'netfIex'],
            'instagram': ['instgram', 'instagr4m', 'inst4gram', '1nstagram'],
            'whatsapp': ['whatsappp', 'whats4pp', 'whatsapp1', 'w4atsapp'],
            'bank': ['bank1', 'b4nk', 'bangk', 'banck']
        }
        
    def extract_true_domain(self, url):
        """แยกโดเมนจริง (ป้องกัน subdomain sandwich)"""
        try:
            extracted = tldextract.extract(url)
            true_domain = f"{extracted.domain}.{extracted.suffix}"
            subdomain = extracted.subdomain
            return true_domain, subdomain
        except:
            return "", ""
    
    def detect_homograph_attack(self, url):
        """ตรวจจับ Homograph/Homoglyph Attack"""
        findings = []
        risk = 0
        
        # ตรวจจับตัวอักษรคล้าย
        homoglyph_pattern = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
            'rn': 'm', 'vv': 'w', 'cl': 'd', 'l1': 'll', 'vv': 'w'
        }
        
        url_lower = url.lower()
        for fake, real in homoglyph_pattern.items():
            if fake in url_lower:
                findings.append(f"⚠️ พบอักขระปลอม: '{fake}' แทน '{real}'")
                risk += 15
        
        # ตรวจจับ Unicode (Punycode)
        if 'xn--' in url:
            findings.append("⚠️ ใช้ Punycode (อาจเป็น Unicode homograph attack)")
            risk += 30
        
        return findings, risk
    
    def detect_subdomain_sandwich(self, url):
        """ตรวจจับ Subdomain Sandwich Attack"""
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.netloc.lower()
            
            # นับจำนวน brand name ที่ซ้อนกัน
            brand_mentioned = []
            for brand in self.brands.keys():
                if brand in hostname:
                    brand_mentioned.append(brand)
            
            if len(brand_mentioned) >= 2:
                return True, f"⚠️ พบหลายแบรนด์ใน URL: {', '.join(brand_mentioned)} (疑似 sandwich attack)", 35
            
            # ตรวจจับจุดเยอะเกินไป
            if hostname.count('.') > 3:
                return True, f"⚠️ มีจุดมากเกินไป: {hostname} (可疑的子域名结构)", 25
                
            return False, "", 0
        except:
            return False, "", 0
    
    def detect_url_redirect_abuse(self, url):
        """ตรวจจับ Redirect abuse (@, //, etc.)"""
        findings = []
        risk = 0
        
        # ตรวจจับ @ symbol
        if '@' in url and not url.startswith('mailto:'):
            parts = url.split('@')
            if len(parts) > 1:
                findings.append(f"⚠️ ใช้ @ เพื่อ redirect ไปยัง: {parts[-1]}")
                risk += 40
        
        # ตรวจจับ multiple slashes
        if '//' in url.replace('https://', '').replace('http://', ''):
            if url.count('//') > 1:
                findings.append("⚠️ มี // ผิดปกติ (อาจเป็น redirect abuse)")
                risk += 20
        
        # ตรวจจับ IP address ใน URL
        ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
        if re.search(ip_pattern, url):
            findings.append("⚠️ ใช้ IP address แทนโดเมน (高风险)")
            risk += 35
        
        return findings, risk
    
    def check_domain_age(self, url):
        """ตรวจสอบอายุโดเมน"""
        try:
            domain, _ = self.extract_true_domain(url)
            if not domain:
                return None, "ไม่สามารถตรวจสอบโดเมนได้", 0
            
            w = whois.whois(domain)
            if w.creation_date:
                # รับมือกับ list
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                age_days = (datetime.now() - creation_date).days
                
                if age_days < 7:
                    return True, f"⚠️ โดเมนอายุ {age_days} วัน (ใหม่มาก！高危)", 50
                elif age_days < 30:
                    return True, f"⚠️ โดเมนอายุ {age_days} วัน (ใหม่，高风险)", 35
                elif age_days < 90:
                    return True, f"⚠️ โดเมนอายุ {age_days} วัน (ค่อนข้างใหม่，中风险)", 20
                else:
                    return False, f"✅ โดเมนอายุ {age_days} วัน", 0
        except:
            return None, "⚠️ ไม่สามารถตรวจสอบอายุโดเมนได้ (อาจถูกซ่อน)", 15
        
        return False, "", 0
    
    def check_ssl_certificate(self, url):
        """ตรวจสอบ SSL Certificate"""
        try:
            if not url.startswith('https'):
                return True, "⚠️ ไม่ใช้ HTTPS (ไม่มีการเข้ารหัส)", 25
            
            # แยก domain
            domain = urlparse(url).netloc or urlparse(url).path
            domain = domain.split(':')[0]
            
            # ตรวจสอบ SSL
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # ตรวจสอบวันหมดอายุ
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expire_date - datetime.now()).days
                    
                    if days_left < 0:
                        return True, f"⚠️ SSL หมดอายุแล้ว", 30
                    elif days_left < 30:
                        return True, f"⚠️ SSL จะหมดอายุใน {days_left} วัน", 15
                    
                    # ตรวจสอบว่าเป็น wildcard หรือไม่
                    if cert.get('subjectAltName'):
                        for san in cert['subjectAltName']:
                            if san[0] == 'DNS' and san[1].startswith('*.'):
                                return True, "⚠️ ใช้ Wildcard SSL (可疑)", 10
                    
                    return False, f"✅ SSL ดี (หมดอายุใน {days_left} วัน)", 0
        except Exception as e:
            return True, f"⚠️ SSL check failed: {str(e)[:50]}", 20
    
    def check_blacklist(self, url):
        """ตรวจสอบ blacklist จาก API ภายนอก (Google Safe Browsing, VirusTotal)"""
        # ต้องขอ API key
        findings = []
        risk = 0
        
        # ตัวอย่าง Google Safe Browsing (ต้องมี API key)
        # ปล่อยไว้ก่อน ต้องสมัคร API key ก่อน
        
        return findings, risk
    
    def detect_typosquatting(self, url):
        """ตรวจจับ Typosquatting"""
        findings = []
        url_lower = url.lower()
        
        for brand, typos in self.brands.items():
            for typo in typos:
                if typo in url_lower:
                    findings.append(f"⚠️ พบการสะกดผิด: '{typo}' (疑似模仿 {brand})")
        
        return findings, len(findings) * 15
    
    def check_url_features(self, url):
        """ตรวจสอบคุณสมบัติ URL ต่างๆ"""
        findings = []
        risk = 0
        
        # ความยาว URL
        if len(url) > 200:
            findings.append(f"⚠️ URL ยาวมาก: {len(url)} ตัวอักษร")
            risk += 20
        elif len(url) > 150:
            findings.append(f"⚠️ URL ยาว: {len(url)} ตัวอักษร")
            risk += 15
        elif len(url) > 100:
            risk += 10
        
        # จำนวนพารามิเตอร์
        parsed = urlparse(url)
        param_count = len(parsed.query.split('&')) if parsed.query else 0
        if param_count > 5:
            findings.append(f"⚠️ มีพารามิเตอร์มาก: {param_count} ตัว")
            risk += 15
        
        # ตรวจจับ suspicious TLD
        domain, _ = self.extract_true_domain(url)
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                findings.append(f"⚠️ ใช้ TLD ที่น่าสงสัย: {tld}")
                risk += 25
        
        return findings, risk
    
    def check_content_similarity(self, url, target_brand=None):
        """ตรวจสอบความคล้ายกับเว็บจริง (ต้องขอ API)"""
        # ปล่อยไว้ก่อน ต้องใช้ external API
        return [], 0
    
    def full_analysis(self, url):
        """วิเคราะห์แบบครบวงจร"""
        results = {
            'is_phishing': False,
            'risk_score': 0,
            'risk_level': 'LOW',
            'findings': [],
            'details': {}
        }
        
        # เก็บผลการวิเคราะห์แต่ละส่วน
        analyses = []
        
        # 1. Homograph Attack
        findings, risk = self.detect_homograph_attack(url)
        results['findings'].extend(findings)
        results['risk_score'] += risk
        analyses.append(('Homograph', risk, findings))
        
        # 2. Subdomain Sandwich
        is_sandwich, msg, risk = self.detect_subdomain_sandwich(url)
        if is_sandwich:
            results['findings'].append(msg)
            results['risk_score'] += risk
        analyses.append(('Subdomain Sandwich', risk if is_sandwich else 0, [msg] if is_sandwich else []))
        
        # 3. Redirect Abuse
        findings, risk = self.detect_url_redirect_abuse(url)
        results['findings'].extend(findings)
        results['risk_score'] += risk
        analyses.append(('Redirect Abuse', risk, findings))
        
        # 4. Domain Age
        is_suspicious, msg, risk = self.check_domain_age(url)
        if is_suspicious:
            results['findings'].append(msg)
            results['risk_score'] += risk
        analyses.append(('Domain Age', risk if is_suspicious else 0, [msg] if is_suspicious else []))
        
        # 5. SSL Certificate
        is_suspicious, msg, risk = self.check_ssl_certificate(url)
        if is_suspicious:
            results['findings'].append(msg)
            results['risk_score'] += risk
        analyses.append(('SSL Certificate', risk if is_suspicious else 0, [msg] if is_suspicious else []))
        
        # 6. Typosquatting
        findings, risk = self.detect_typosquatting(url)
        results['findings'].extend(findings)
        results['risk_score'] += risk
        analyses.append(('Typosquatting', risk, findings))
        
        # 7. URL Features
        findings, risk = self.check_url_features(url)
        results['findings'].extend(findings)
        results['risk_score'] += risk
        analyses.append(('URL Features', risk, findings))
        
        # กำหนดระดับความเสี่ยง
        if results['risk_score'] >= 70:
            results['risk_level'] = 'HIGH RISK'
            results['is_phishing'] = True
        elif results['risk_score'] >= 40:
            results['risk_level'] = 'MEDIUM RISK'
            results['is_phishing'] = True
        else:
            results['risk_level'] = 'LOW RISK'
            results['is_phishing'] = False
        
        results['details'] = analyses
        return results

# สร้าง instance สำหรับใช้งาน
detector = AdvancedPhishingDetector()