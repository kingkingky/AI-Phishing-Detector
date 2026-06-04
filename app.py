from flask import Flask, render_template, request, jsonify
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import re
import sqlite3
import joblib
import os
from datetime import datetime
import urllib.parse
import tldextract
import whois
import socket
import ssl

# import advanced detector
from advanced_detector import detector

app = Flask(__name__)

# -----------------------------
# Load Models
# -----------------------------
model = joblib.load("model/phishing_model.pkl")
url_model = joblib.load("model/url_model.pkl")
vectorizer = joblib.load("model/vectorizer.pkl")

# -----------------------------
# Initialize Database
# -----------------------------
def init_db():
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT,
            result TEXT,
            risk_level TEXT,
            confidence REAL,
            risk_score INTEGER,
            reasons TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# -----------------------------
# URL Feature Extraction (Original)
# -----------------------------
def extract_url_features(url):
    features = []
    features.append(len(url))
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(1 if "https" in url else 0)
    
    suspicious_keywords = ["login", "verify", "secure", "bank", "bonus", "free", "update"]
    suspicious_score = 0
    for word in suspicious_keywords:
        if word in url.lower():
            suspicious_score += 1
    features.append(suspicious_score)
    
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    features.append(1 if re.search(ip_pattern, url) else 0)
    return features

# -----------------------------
# Basic URL Analysis
# -----------------------------
def analyze_url(url):
    findings = []
    if len(url) > 75:
        findings.append("Long URL")
    if url.count(".") > 3:
        findings.append("Many subdomains")
    if "@" in url:
        findings.append("Contains @ symbol")
    if "-" in url:
        findings.append("Contains hyphen")
    if re.search(r"(\d{1,3}\.){3}\d{1,3}", url):
        findings.append("IP Address Detected")
    return findings

# -----------------------------
# Advanced URL Analysis using Detector
# -----------------------------
def analyze_url_advanced(url):
    """ใช้ advanced detector วิเคราะห์ URL แบบละเอียด"""
    result = detector.full_analysis(url)
    return result

# -----------------------------
# Home Route (Upgraded)
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    confidence = 0
    risk_level = ""
    reasons = []
    risk_score = 0
    url_report = []
    advanced_result = None
    
    if request.method == "POST":
        text = request.form["message"]
        
        # ตรวจจับว่าเป็น URL หรือไม่
        is_url = "http" in text or ".com" in text or ".xyz" in text or ".net" in text or ".org" in text
        
        # ใช้ Advanced Detector ถ้าเป็น URL
        if is_url:
            advanced_result = analyze_url_advanced(text)
            
            # เพิ่มผลลัพธ์จาก advanced detector
            reasons.extend(advanced_result['findings'])
            risk_score += advanced_result['risk_score']
            
            # ใช้ risk level จาก advanced detector
            if advanced_result['risk_level'] == "HIGH RISK":
                risk_level = "HIGH RISK"
            elif advanced_result['risk_level'] == "MEDIUM RISK" and risk_level != "HIGH RISK":
                risk_level = "MEDIUM RISK"
            
            url_report = advanced_result['findings']
        
        # Text Prediction ด้วย Machine Learning
        text_vector = vectorizer.transform([text])
        text_prediction = model.predict(text_vector)[0]
        text_probability = model.predict_proba(text_vector)[0]
        confidence = round(max(text_probability) * 100, 2)
        
        # URL Prediction (Original Model)
        url_prediction = 0
        if is_url:
            url_features = extract_url_features(text)
            url_prediction = url_model.predict([url_features])[0]
        
        # Keyword-based Detection (เพิ่มเติม)
        phishing_keywords = {
            'login': 20, 'verify': 20, 'secure': 15, 'bank': 25,
            'free': 10, 'bonus': 10, 'update': 15, 'confirm': 20,
            'account': 15, 'password': 25, 'credit': 30, 'urgent': 25,
            'verify your account': 30, 'security alert': 25, 'unusual activity': 25,
            'click here': 15, 'reset password': 20, 'payment failed': 25
        }
        
        keyword_reasons = []
        keywords_risk = 0
        
        for keyword, points in phishing_keywords.items():
            if keyword in text.lower():
                if keyword not in [r.lower() for r in keyword_reasons]:  # ไม่ให้ซ้ำ
                    keyword_reasons.append(f"พบคำสำคัญ: {keyword}")
                    keywords_risk += points
        
        reasons.extend(keyword_reasons)
        risk_score += keywords_risk
        
        # ตรวจจับ URL shortener
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'short.link']
        for shortener in shorteners:
            if shortener in text.lower():
                reasons.append(f"⚠️ ใช้ URL ย่อ: {shortener}")
                risk_score += 20
        
        # ตรวจจับ IP Address
        ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
        if re.search(ip_pattern, text):
            reasons.append("⚠️ ใช้ IP Address แทนโดเมน")
            risk_score += 30
        
        # ตรวจจับ suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.online', '.site', '.click']
        for tld in suspicious_tlds:
            if tld in text.lower():
                reasons.append(f"⚠️ ใช้ TLD ที่น่าสงสัย: {tld}")
                risk_score += 20
        
        # ตัดสินใจผลลัพธ์สุดท้าย
        if risk_score >= 70 or text_prediction == 1 or url_prediction == 1:
            result = "⚠️ PHISHING THREAT DETECTED"
            if risk_level != "HIGH RISK":
                risk_level = "HIGH RISK"
        elif risk_score >= 40:
            result = "⚠️ SUSPICIOUS CONTENT DETECTED"
            if risk_level != "HIGH RISK":
                risk_level = "MEDIUM RISK"
        else:
            result = "✅ SAFE CONTENT"
            if not risk_level:
                risk_level = "LOW RISK"
        
        # ปรับ confidence ตาม risk score
        confidence = min(100, max(confidence, risk_score))
        
        # จำกัดจำนวนเหตุผลไม่ให้ยาวเกินไป
        if len(reasons) > 15:
            reasons = reasons[:15]
        
        # บันทึกข้อมูลในฐานข้อมูล
        conn = sqlite3.connect("threats.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO detections (message, result, risk_level, confidence, risk_score, reasons)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (text[:500], result, risk_level, confidence, risk_score, ", ".join(reasons[:10])))
        conn.commit()
        conn.close()
        
        return render_template("index.html", 
                             result=result,
                             confidence=confidence,
                             risk_level=risk_level,
                             risk_score=risk_score,
                             reasons=reasons,
                             url_report=url_report)
    
    return render_template("index.html", result=result, confidence=confidence,
                         risk_level=risk_level, risk_score=0, reasons=[],
                         url_report=[])

# -----------------------------
# Dashboard Route
# -----------------------------
@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM detections ORDER BY id DESC")
    data = cursor.fetchall()
    
    total_count = len(data)
    phishing_count = 0
    safe_count = 0
    high_risk_count = 0
    medium_risk_count = 0
    low_risk_count = 0
    
    for row in data:
        if "PHISHING" in row[2] or "SUSPICIOUS" in row[2]:
            phishing_count += 1
        else:
            safe_count += 1
        
        # นับตามระดับความเสี่ยง
        if row[3] == "HIGH RISK":
            high_risk_count += 1
        elif row[3] == "MEDIUM RISK":
            medium_risk_count += 1
        else:
            low_risk_count += 1
    
    # คำนวณค่าเฉลี่ย
    cursor.execute("SELECT AVG(risk_score) FROM detections")
    avg_risk_result = cursor.fetchone()[0]
    avg_risk = avg_risk_result if avg_risk_result is not None else 0
    
    cursor.execute("SELECT AVG(confidence) FROM detections")
    avg_conf_result = cursor.fetchone()[0]
    avg_conf = avg_conf_result if avg_conf_result is not None else 0
    
    os.makedirs("static/charts", exist_ok=True)
    
    # Pie Chart - จำแนกตามความเสี่ยง
    plt.figure(figsize=(5,5))
    labels = ['HIGH RISK', 'MEDIUM RISK', 'LOW RISK']
    sizes = [high_risk_count, medium_risk_count, low_risk_count]
    colors = ['#ef4444', '#eab308', '#22c55e']
    
    if sum(sizes) == 0:
        sizes = [1, 1, 1]
    
    plt.pie(sizes, labels=labels, autopct="%1.1f%%", colors=colors)
    plt.title("Threat Risk Distribution")
    plt.tight_layout()
    plt.savefig("static/charts/threat_chart.png")
    plt.close()
    
    # Timeline Graph
    cursor.execute("""
        SELECT DATE(timestamp), COUNT(*), AVG(risk_score)
        FROM detections 
        GROUP BY DATE(timestamp)
        ORDER BY DATE(timestamp)
    """)
    timeline_data = cursor.fetchall()
    
    dates = []
    counts = []
    avg_risks = []
    
    for row in timeline_data:
        dates.append(row[0])
        counts.append(row[1])
        avg_risks.append(round(row[2] or 0, 1))
    
    if dates:
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 8))
        
        # กราฟจำนวน
        ax1.plot(dates, counts, marker='o', linewidth=2, color='#38bdf8', markersize=6)
        ax1.set_title('Number of Detections Over Time')
        ax1.set_ylabel('Number of Scans')
        ax1.grid(True, alpha=0.3)
        ax1.tick_params(axis='x', rotation=45)
        
        # กราฟคะแนนความเสี่ยงเฉลี่ย
        ax2.plot(dates, avg_risks, marker='s', linewidth=2, color='#ef4444', markersize=6)
        ax2.set_title('Average Risk Score Over Time')
        ax2.set_xlabel('Date')
        ax2.set_ylabel('Risk Score (0-100)')
        ax2.grid(True, alpha=0.3)
        ax2.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig("static/charts/timeline_chart.png")
        plt.close()
    
    conn.close()
    
    return render_template("dashboard.html", 
                         data=data,
                         total_count=total_count,
                         phishing_count=phishing_count,
                         safe_count=safe_count,
                         avg_risk=round(avg_risk, 2),
                         avg_confidence=round(avg_conf, 2),
                         high_risk_count=high_risk_count,
                         medium_risk_count=medium_risk_count,
                         low_risk_count=low_risk_count)

# -----------------------------
# History Route
# -----------------------------
@app.route("/history")
def history():
    conn = sqlite3.connect("threats.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM detections 
        ORDER BY id DESC 
        LIMIT 100
    """)
    data = cursor.fetchall()
    conn.close()
    
    return render_template("history.html", data=data)

# -----------------------------
# API Endpoint for External Check
# -----------------------------
@app.route("/api/check", methods=["POST"])
def api_check():
    """API สำหรับตรวจสอบ URL แบบ real-time"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        url = data.get('url', '')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        result = detector.full_analysis(url)
        
        return jsonify({
            'url': url,
            'is_phishing': result['is_phishing'],
            'risk_score': result['risk_score'],
            'risk_level': result['risk_level'],
            'findings': result['findings'],
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# -----------------------------
# Clear Database Route (Admin)
# -----------------------------
@app.route("/admin/clear", methods=["POST"])
def clear_database():
    """ล้างข้อมูลทั้งหมดในฐานข้อมูล (สำหรับทดสอบ)"""
    try:
        conn = sqlite3.connect("threats.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM detections")
        conn.commit()
        conn.close()
        return jsonify({'message': 'Database cleared successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    init_db()  # Initialize database
    print("=" * 50)
    print("🚀 AI Phishing Detector Started")
    print("📊 Dashboard: http://127.0.0.1:5000/dashboard")
    print("🔍 Main Page: http://127.0.0.1:5000")
    print("📡 API Endpoint: http://127.0.0.1:5000/api/check")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)