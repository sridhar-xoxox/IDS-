import os
import sqlite3
import pickle
import numpy as np
import json
import time
import threading
from datetime import datetime
from functools import wraps
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, flash, send_file, make_response)
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
import io

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'df72a1e3b5e4f4b23d906e57cd67c4b1')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, 'models')
if os.environ.get("VERCEL"):
    DB_PATH = '/tmp/database.db'
else:
    DB_PATH = os.path.join(BASE_DIR, 'database.db')

# ─── Load ML Models ───────────────────────────────────────────────────────────
try:
    with open(os.path.join(MODEL_DIR, 'best_model.pkl'), 'rb') as f:
        ml_model = pickle.load(f)
    with open(os.path.join(MODEL_DIR, 'scaler.pkl'), 'rb') as f:
        scaler = pickle.load(f)
    with open(os.path.join(MODEL_DIR, 'label_encoder.pkl'), 'rb') as f:
        label_encoder = pickle.load(f)
    MODEL_LOADED = True
    print("[OK] ML models loaded successfully.")
except Exception as e:
    MODEL_LOADED = False
    print(f"[WARN] Could not load models: {e}")

FEATURES = [
    'Flow_Duration', 'Tot_Fwd_Pkts', 'Tot_Bwd_Pkts', 'Fwd_Pkt_Len_Mean',
    'Bwd_Pkt_Len_Mean', 'Flow_Byts_s', 'Flow_Pkts_s', 'Flow_IAT_Mean',
    'Fwd_Header_Len', 'Bwd_Header_Len', 'Flow_Flags', 'Protocol'
]

LABEL_NAMES = {
    0: 'BENIGN', 1: 'Botnet', 2: 'DDoS', 3: 'DoS', 4: 'PortScan', 5: 'WebAttack'
}

# ─── Signature Rules ──────────────────────────────────────────────────────────
def signature_detection(row):
    """Rule-based IDS similar to Snort."""
    if row['Flow_Pkts_s'] > 1000 and row['Tot_Fwd_Pkts'] > 1200:
        return 'DoS Attack'
    if row['Flow_Byts_s'] > 200000 and row['Flow_Pkts_s'] > 2500:
        return 'DDoS Attack'
    if row['Tot_Fwd_Pkts'] < 50 and row['Flow_Duration'] < 0.5:
        return 'Port Scan'
    if row['Flow_Duration'] < 1 and row['Tot_Fwd_Pkts'] > 300:
        return 'Brute Force'
    if row['Protocol'] == 6 and row['Fwd_Pkt_Len_Mean'] > 500:
        return 'Web Attack'
    if row['Flow_Byts_s'] > 500000 and row['Flow_Duration'] > 10:
        return 'Data Exfiltration'
    if row['Flow_Pkts_s'] < 10 and row['Flow_Duration'] > 30:
        return 'Slowloris'
    if row['Flow_Flags'] == 2 and row['Flow_Pkts_s'] > 1500:
        return 'SYN Flood'
    if row['Protocol'] == 17 and row['Flow_Pkts_s'] > 2000:
        return 'UDP Flood'
    if row['Tot_Bwd_Pkts'] > 1000 and row['Flow_Byts_s'] > 100000:
        return 'Botnet Traffic'
    return None

# ─── Recommendations ──────────────────────────────────────────────────────────
RECOMMENDATIONS = {
    'BENIGN': {
        'severity': 'low',
        'color': '#22c55e',
        'icon': '✅',
        'title': 'Normal Traffic Detected',
        'text': 'The analyzed network flow exhibits normal traffic characteristics and poses no immediate threat to your infrastructure. All packet metrics, flow durations, and protocol behaviors fall within expected baseline parameters. Maintaining this traffic profile indicates a healthy network environment. Continue monitoring periodically to ensure no gradual deviation from baseline behavior occurs. Regular network baselining and traffic profiling are essential components of a proactive security posture. Implement continuous monitoring dashboards and set up automated alerts for any statistical anomalies that deviate beyond two standard deviations from your established baseline.',
        'steps': ['Maintain regular traffic baseline', 'Continue periodic monitoring', 'Keep security patches updated', 'Review firewall rules quarterly']
    },
    'DoS Attack': {
        'severity': 'critical',
        'color': '#ef4444',
        'icon': '🔥',
        'title': 'Denial of Service Attack Detected',
        'text': 'A Denial of Service (DoS) attack has been detected, characterized by an overwhelming flood of packets designed to exhaust server resources and render services unavailable to legitimate users. This attack exploits the finite capacity of your network infrastructure by sending traffic at rates exceeding normal operational parameters. The high packet-per-second rate combined with large forward packet counts are clear indicators of volumetric DoS activity. Immediate action is required to prevent service disruption affecting end users and business operations. Activate your incident response plan and engage upstream providers for traffic scrubbing. Implement rate limiting on affected interfaces and consider deploying a Web Application Firewall with DoS mitigation capabilities to absorb and filter malicious traffic automatically.',
        'steps': ['Enable rate limiting immediately', 'Block source IP at perimeter firewall', 'Contact ISP for upstream filtering', 'Activate DDoS mitigation service', 'Monitor bandwidth utilization']
    },
    'DDoS Attack': {
        'severity': 'critical',
        'color': '#ef4444',
        'icon': '💥',
        'title': 'Distributed Denial of Service Attack Detected',
        'text': 'A Distributed Denial of Service (DDoS) attack is actively targeting your infrastructure, originating from multiple distributed sources to overwhelm your network capacity. This coordinated assault sends millions of packets per second from geographically distributed botnets, making source-based blocking ineffective. The extremely high byte-per-second and packet-per-second values confirm a large-scale volumetric attack that can saturate your upstream bandwidth links. DDoS attacks can cause prolonged outages costing organizations thousands of dollars per minute. Immediately engage your DDoS mitigation provider and activate traffic scrubbing centers to redirect and filter malicious flows before they reach your origin infrastructure. Implement anycast network diffusion and deploy CDN-based protection to distribute attack traffic across a global network of scrubbing nodes.',
        'steps': ['Engage DDoS mitigation provider', 'Enable geo-blocking for suspicious regions', 'Deploy CDN protection layer', 'Implement anycast diffusion', 'Notify upstream ISP for null routing']
    },
    'Port Scan': {
        'severity': 'medium',
        'color': '#f59e0b',
        'icon': '🔍',
        'title': 'Port Scanning Activity Detected',
        'text': 'Port scanning reconnaissance activity has been detected, indicating an attacker is systematically probing your network to identify open ports and discover potentially vulnerable services. Port scanning is typically the first stage of a multi-phase cyberattack, used by threat actors to map your attack surface before launching targeted exploits. The short flow durations combined with low packet counts are consistent with TCP SYN, UDP, or stealth FIN scan patterns. This activity is highly likely to precede a more serious attack attempt targeting discovered open services. Immediately review your firewall rules to ensure only necessary ports are exposed, disable or close any unnecessary services, and consider implementing port knocking for sensitive administration interfaces. Deploy an intrusion prevention system (IPS) to automatically block hosts exhibiting scan behavior.',
        'steps': ['Block scanning IP at firewall', 'Review and close unnecessary open ports', 'Enable IPS scan detection rules', 'Implement port knocking for SSH', 'Alert security team for investigation']
    },
    'Brute Force': {
        'severity': 'high',
        'color': '#f97316',
        'icon': '🔓',
        'title': 'Brute Force Attack Detected',
        'text': 'A brute force credential stuffing attack has been identified, where an automated tool is systematically attempting thousands of username and password combinations to gain unauthorized access to your systems. The high packet volume within an extremely short time window is characteristic of automated brute force tools such as Hydra, Medusa, or custom scripts targeting SSH, RDP, FTP, or web application login endpoints. Successful brute force attacks can lead to complete system compromise, data exfiltration, and lateral movement through your network. Implement account lockout policies that temporarily disable accounts after a defined number of failed attempts. Deploy multi-factor authentication (MFA) on all critical access points, as this single control can neutralize virtually all credential-based attacks. Consider implementing CAPTCHA on web login forms and geofencing for administrative access.',
        'steps': ['Enforce account lockout policy', 'Enable multi-factor authentication', 'Block source IP immediately', 'Review authentication logs', 'Implement CAPTCHA on login pages']
    },
    'Web Attack': {
        'severity': 'high',
        'color': '#f97316',
        'icon': '🕸️',
        'title': 'Web Application Attack Detected',
        'text': 'A web application attack has been detected targeting your HTTP/HTTPS services, with payload sizes indicating SQL injection, Cross-Site Scripting (XSS), or command injection attempts. Web attacks exploit vulnerabilities in web application code to gain unauthorized access, steal sensitive data, or execute arbitrary commands on the server. The TCP protocol usage with abnormally large forward packet lengths is consistent with attackers sending crafted malicious payloads designed to bypass input validation. These attacks can lead to database breaches, session hijacking, privilege escalation, and complete web server compromise. Deploy a Web Application Firewall (WAF) with updated OWASP Core Rule Set (CRS) signatures to detect and block common attack patterns. Immediately audit your application code for SQL injection and XSS vulnerabilities, and implement parameterized queries for all database interactions.',
        'steps': ['Deploy Web Application Firewall (WAF)', 'Audit application code for vulnerabilities', 'Implement input sanitization', 'Enable HTTPS with HSTS headers', 'Conduct OWASP penetration testing']
    },
    'Data Exfiltration': {
        'severity': 'critical',
        'color': '#ef4444',
        'icon': '📤',
        'title': 'Data Exfiltration Attempt Detected',
        'text': 'Active data exfiltration has been detected, indicating that sensitive data is being systematically transferred out of your network to external destinations. The combination of extremely high byte transfer rates sustained over extended flow durations is a strong indicator of an attacker or malicious insider extracting large volumes of confidential data. Data exfiltration is typically the final stage of an Advanced Persistent Threat (APT) campaign, occurring after initial compromise, lateral movement, and data staging. The financial and reputational consequences can be catastrophic, potentially triggering regulatory penalties under GDPR, HIPAA, or PCI-DSS. Immediately isolate affected systems, block all outbound traffic to the identified destination, and initiate forensic investigation. Engage your Data Loss Prevention (DLP) solution and notify your legal and compliance teams as a potential data breach may require regulatory notification.',
        'steps': ['Isolate affected systems immediately', 'Block outbound traffic to destination', 'Enable DLP monitoring rules', 'Initiate forensic investigation', 'Notify compliance/legal team']
    },
    'Slowloris': {
        'severity': 'medium',
        'color': '#f59e0b',
        'icon': '🐌',
        'title': 'Slowloris DoS Attack Detected',
        'text': 'A Slowloris slow HTTP denial-of-service attack has been detected, targeting your web server by opening many connections and keeping them alive indefinitely with partial HTTP requests. Unlike volumetric attacks, Slowloris consumes server thread pools by sending just enough data to keep connections open without completing requests, eventually exhausting available connection slots. The very low packet rate sustained over extended flow duration is the defining signature of this elegant but devastating attack. Apache and other threaded web servers are particularly vulnerable to this attack vector. Implement connection timeout settings to terminate connections that fail to complete requests within acceptable timeframes. Consider migrating to event-driven web servers like Nginx that handle connections asynchronously and are inherently resistant to Slowloris-style attacks.',
        'steps': ['Configure connection timeout limits', 'Enable request rate limiting', 'Migrate to Nginx/event-driven server', 'Implement IP connection limits', 'Deploy anti-Slowloris module']
    },
    'SYN Flood': {
        'severity': 'high',
        'color': '#f97316',
        'icon': '🌊',
        'title': 'TCP SYN Flood Attack Detected',
        'text': 'A TCP SYN flood attack has been detected, exploiting the TCP three-way handshake mechanism to consume server resources by sending large volumes of SYN packets without completing the connection handshake. Each unanswered SYN packet creates a half-open connection entry in the TCP connection table, eventually exhausting available connection slots and preventing legitimate users from establishing connections. The detection of SYN-only flag packets at extremely high rates is a definitive signature of this classic but highly effective denial-of-service technique. Enable SYN cookies at the kernel level to handle SYN requests without maintaining connection state, effectively neutralizing SYN flood attacks. Implement SYN rate limiting on your border routers and firewalls, and configure your network infrastructure to drop incomplete TCP handshakes that exceed defined thresholds.',
        'steps': ['Enable SYN cookies at kernel level', 'Configure SYN rate limiting on router', 'Deploy stateful firewall inspection', 'Implement TCP half-open connection limits', 'Enable DDoS scrubbing service']
    },
    'UDP Flood': {
        'severity': 'high',
        'color': '#f97316',
        'icon': '💧',
        'title': 'UDP Flood Attack Detected',
        'text': 'A UDP flood attack has been detected, overwhelming your network with high volumes of User Datagram Protocol packets targeting random ports to exhaust bandwidth and force servers to process and respond to unreachable port notifications. UDP\'s connectionless nature makes spoofing source addresses trivial, enabling amplification attacks using services like DNS, NTP, and SSDP that can return responses many times larger than the original request. The extremely high UDP packet rate on Protocol 17 definitively confirms this volumetric flooding attack vector. Implement egress filtering to prevent UDP source address spoofing from your network, and deploy upstream traffic scrubbing to absorb volumetric floods before they reach your infrastructure. Configure rate limiting for UDP traffic at the perimeter and consider disabling unnecessary UDP services that could be exploited for amplification.',
        'steps': ['Implement UDP rate limiting at perimeter', 'Enable ingress/egress packet filtering', 'Disable unused UDP services', 'Deploy upstream traffic scrubbing', 'Contact ISP for null routing if needed']
    },
    'Botnet Traffic': {
        'severity': 'critical',
        'color': '#ef4444',
        'icon': '🤖',
        'title': 'Botnet Command & Control Traffic Detected',
        'text': 'Botnet command-and-control (C2) traffic has been detected, indicating that one or more systems in your network have been compromised and are communicating with botnet infrastructure to receive attack commands or exfiltrate stolen data. The high backward packet count combined with significant byte transfer rates is characteristic of bots receiving instructions or uploading harvested credentials and sensitive information to C2 servers. Botnet infections typically indicate a deeper compromise that may have been present for days, weeks, or months before detection. The infected systems may be participating in DDoS attacks, sending spam, mining cryptocurrency, or serving as persistent access points for further intrusion. Immediately isolate all suspected bot-infected systems from the network, conduct comprehensive malware analysis and forensic investigation, and perform a full security audit of adjacent systems that may have been laterally compromised.',
        'steps': ['Isolate infected systems immediately', 'Block C2 server IPs/domains at DNS', 'Run comprehensive malware scan', 'Reset all credentials on affected systems', 'Conduct full forensic investigation']
    },
    'Botnet': {
        'severity': 'critical',
        'color': '#ef4444',
        'icon': '🤖',
        'title': 'Botnet Activity Detected',
        'text': 'Botnet activity has been identified through machine learning analysis of traffic patterns, indicating potential command-and-control communication or coordinated attack participation. Botnets represent one of the most persistent and dangerous threats in modern cybersecurity, enabling threat actors to conduct large-scale attacks while maintaining anonymity through distributed infrastructure. ML detection of botnet patterns often reveals subtle behavioral anomalies that signature-based systems miss, such as periodic beaconing, encrypted C2 channels, and domain generation algorithm (DGA) based communications. Infected hosts within your network may be harvesting credentials, conducting reconnaissance, or participating in attacks against external targets, creating legal and reputational liability. Implement DNS sinkholing to redirect botnet C2 domain lookups and conduct thorough endpoint investigation using EDR tools.',
        'steps': ['Implement DNS sinkholing for C2 domains', 'Deploy EDR on all endpoints', 'Review and audit all network connections', 'Block outbound connections to threat intel feeds', 'Reset compromised credentials']
    },
    'DDoS': {
        'severity': 'critical',
        'color': '#ef4444',
        'icon': '💥',
        'title': 'DDoS Pattern Detected (ML Analysis)',
        'text': 'Machine learning analysis has identified DDoS attack patterns in the analyzed traffic flow. The ensemble model detected statistical anomalies in packet distribution, inter-arrival times, and byte ratios consistent with distributed flooding attacks even without triggering specific signature rules. This indicates a potentially sophisticated or low-rate DDoS variant designed to evade traditional rule-based detection. Such evasive DDoS techniques represent an advanced threat requiring adaptive mitigation strategies. Activate your DDoS response playbook and engage specialized mitigation services capable of behavioral-based traffic analysis. Implement traffic shaping and queuing policies to prioritize legitimate traffic even under attack conditions.',
        'steps': ['Activate DDoS response playbook', 'Engage behavioral mitigation service', 'Implement traffic shaping policies', 'Monitor bandwidth consumption trends', 'Coordinate with upstream providers']
    },
    'DoS': {
        'severity': 'critical',
        'color': '#ef4444',
        'icon': '🔥',
        'title': 'DoS Pattern Detected (ML Analysis)',
        'text': 'The machine learning model has detected Denial of Service attack characteristics through statistical analysis of network flow features. The Random Forest classifier identified patterns in packet timing, size distribution, and protocol behavior that match known DoS attack profiles from training data. Even without triggering explicit signature rules, the behavioral fingerprint of this traffic is highly consistent with resource exhaustion attacks. Immediate defensive action is warranted to prevent service degradation. Implement rate limiting at the nearest network boundary and enable your perimeter defense mechanisms to absorb and filter the malicious traffic flow.',
        'steps': ['Enable rate limiting on affected interface', 'Activate perimeter defense systems', 'Monitor resource utilization closely', 'Prepare service failover if needed', 'Document incident for analysis']
    },
    'PortScan': {
        'severity': 'medium',
        'color': '#f59e0b',
        'icon': '🔍',
        'title': 'Port Scan Detected (ML Analysis)',
        'text': 'ML-based analysis has identified port scanning behavior in the analyzed traffic. The model detected characteristics typical of network reconnaissance including probe patterns and connection attempt signatures across multiple service ports. Port scanning is an early-stage attack precursor that warrants immediate investigation and defensive response.',
        'steps': ['Block scanning source at firewall', 'Review exposed services inventory', 'Enable IPS detection signatures', 'Monitor for follow-up attack attempts', 'Document in threat intelligence feed']
    },
    'WebAttack': {
        'severity': 'high',
        'color': '#f97316',
        'icon': '🕸️',
        'title': 'Web Attack Detected (ML Analysis)',
        'text': 'Machine learning detection has flagged web application attack behavior in the traffic analysis. The model identified protocol usage patterns, payload characteristics, and connection behaviors consistent with common web attack categories including injection attacks, authentication bypasses, and session manipulation attempts targeting your web application layer.',
        'steps': ['Enable WAF with OWASP CRS rules', 'Audit web application for vulnerabilities', 'Review recent HTTP access logs', 'Implement input validation', 'Run automated vulnerability scanner']
    },
}

def get_recommendation(attack_type):
    """Return recommendation dict for given attack type."""
    rec = RECOMMENDATIONS.get(attack_type, RECOMMENDATIONS.get('BENIGN'))
    if rec is None:
        rec = {
            'severity': 'medium',
            'color': '#6366f1',
            'icon': '⚠️',
            'title': f'Anomalous Traffic: {attack_type}',
            'text': f'An anomalous traffic pattern classified as "{attack_type}" has been detected. While this pattern does not match known attack signatures precisely, the machine learning model has flagged this traffic as potentially malicious based on its learned understanding of attack behavioral profiles. Conduct manual investigation of the associated network flows and review system logs for corroborating evidence of malicious activity. Consider submitting this traffic sample to your threat intelligence team for further analysis.',
            'steps': ['Investigate flagged traffic manually', 'Review associated system logs', 'Submit sample to threat intel team', 'Monitor for recurring patterns', 'Update detection rules if confirmed malicious']
        }
    return rec

# ─── Database ─────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        role TEXT DEFAULT 'analyst'
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        prediction TEXT NOT NULL,
        detection_method TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL DEFAULT 0.0,
        features TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

init_db()

# ─── Auth Decorator ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        db.close()
        if user and check_password_hash(user['password'], password):
            session['user_id']   = user['id']
            session['username']  = user['username']
            session['email']     = user['email']
            session['role']      = user['role']
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return render_template('signup.html')
        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            db = get_db()
            db.execute('INSERT INTO users (username, email, password) VALUES (?,?,?)',
                       (username, email, hashed))
            db.commit()
            db.close()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    uid = session['user_id']
    total   = db.execute('SELECT COUNT(*) as c FROM predictions WHERE user_id=?', (uid,)).fetchone()['c']
    attacks = db.execute("SELECT COUNT(*) as c FROM predictions WHERE user_id=? AND prediction!='BENIGN'", (uid,)).fetchone()['c']
    normal  = total - attacks
    top_row = db.execute(
        "SELECT prediction, COUNT(*) as c FROM predictions WHERE user_id=? AND prediction!='BENIGN' GROUP BY prediction ORDER BY c DESC LIMIT 1",
        (uid,)).fetchone()
    top_attack = top_row['prediction'] if top_row else 'N/A'
    # Chart data
    dist = db.execute(
        'SELECT prediction, COUNT(*) as c FROM predictions WHERE user_id=? GROUP BY prediction', (uid,)).fetchall()
    # Recent 5
    recent = db.execute(
        'SELECT * FROM predictions WHERE user_id=? ORDER BY timestamp DESC LIMIT 5', (uid,)).fetchall()
    # All-time stats
    sig_count = db.execute("SELECT COUNT(*) as c FROM predictions WHERE user_id=? AND detection_method='Signature'", (uid,)).fetchone()['c']
    ml_count  = db.execute("SELECT COUNT(*) as c FROM predictions WHERE user_id=? AND detection_method='ML Model'", (uid,)).fetchone()['c']
    db.close()
    chart_labels = [r['prediction'] for r in dist]
    chart_values = [r['c'] for r in dist]
    return render_template('dashboard.html',
        total=total, attacks=attacks, normal=normal, top_attack=top_attack,
        chart_labels=json.dumps(chart_labels), chart_values=json.dumps(chart_values),
        recent=recent, sig_count=sig_count, ml_count=ml_count)

@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    if request.method == 'GET':
        return render_template('predict.html')

    # Parse input
    try:
        row = {
            'Flow_Duration':    float(request.form.get('Flow_Duration', 0)),
            'Tot_Fwd_Pkts':     float(request.form.get('Tot_Fwd_Pkts', 0)),
            'Tot_Bwd_Pkts':     float(request.form.get('Tot_Bwd_Pkts', 0)),
            'Fwd_Pkt_Len_Mean': float(request.form.get('Fwd_Pkt_Len_Mean', 0)),
            'Bwd_Pkt_Len_Mean': float(request.form.get('Bwd_Pkt_Len_Mean', 0)),
            'Flow_Byts_s':      float(request.form.get('Flow_Byts_s', 0)),
            'Flow_Pkts_s':      float(request.form.get('Flow_Pkts_s', 0)),
            'Flow_IAT_Mean':    float(request.form.get('Flow_IAT_Mean', 0)),
            'Fwd_Header_Len':   float(request.form.get('Fwd_Header_Len', 0)),
            'Bwd_Header_Len':   float(request.form.get('Bwd_Header_Len', 0)),
            'Flow_Flags':       float(request.form.get('Flow_Flags', 0)),
            'Protocol':         float(request.form.get('Protocol', 0)),
        }
    except ValueError:
        flash('Invalid input values. Please enter valid numbers.', 'danger')
        return render_template('predict.html')

    # Step 1: Signature detection
    sig_result = signature_detection(row)
    confidence = 100.0
    detection_method = 'Signature'
    prediction = sig_result

    # Step 2: ML fallback
    if sig_result is None:
        detection_method = 'ML Model'
        if MODEL_LOADED:
            try:
                feat_vals = np.array([list(row.values())]).reshape(1, -1)
                scaled    = scaler.transform(feat_vals)
                pred_idx  = ml_model.predict(scaled)[0]
                proba     = ml_model.predict_proba(scaled)[0]
                confidence = round(float(np.max(proba)) * 100, 2)
                if hasattr(label_encoder, 'inverse_transform'):
                    prediction = label_encoder.inverse_transform([pred_idx])[0]
                else:
                    prediction = LABEL_NAMES.get(pred_idx, str(pred_idx))
            except Exception as e:
                prediction = 'BENIGN'
                confidence = 0.0
        else:
            prediction = 'BENIGN'
            confidence = 0.0

    rec = get_recommendation(prediction)

    # Store prediction
    db = get_db()
    db.execute(
        'INSERT INTO predictions (user_id, username, prediction, detection_method, severity, confidence, features, recommendation) VALUES (?,?,?,?,?,?,?,?)',
        (session['user_id'], session['username'], prediction, detection_method,
         rec['severity'], confidence, json.dumps(row), rec['text'][:500])
    )
    db.commit()
    pred_id = db.execute('SELECT last_insert_rowid() as id').fetchone()['id']
    db.close()

    return render_template('result.html',
        prediction=prediction, detection_method=detection_method,
        confidence=confidence, row=row, rec=rec, pred_id=pred_id,
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/history')
@login_required
def history():
    db = get_db()
    records = db.execute(
        'SELECT * FROM predictions WHERE user_id=? ORDER BY timestamp DESC',
        (session['user_id'],)).fetchall()
    db.close()
    return render_template('history.html', records=records)

@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    uid = session['user_id']
    monthly = db.execute(
        "SELECT strftime('%Y-%m', timestamp) as month, COUNT(*) as c FROM predictions WHERE user_id=? GROUP BY month ORDER BY month DESC LIMIT 6",
        (uid,)).fetchall()
    db.close()
    return jsonify({'monthly': [dict(r) for r in monthly]})

@app.route('/download_pdf/<int:pred_id>')
@login_required
def download_pdf(pred_id):
    db = get_db()
    pred = db.execute(
        'SELECT * FROM predictions WHERE id=? AND user_id=?',
        (pred_id, session['user_id'])).fetchone()
    db.close()
    if not pred:
        flash('Prediction not found.', 'danger')
        return redirect(url_for('history'))

    features = json.loads(pred['features'])
    rec = get_recommendation(pred['prediction'])

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=50, leftMargin=50,
                            topMargin=60, bottomMargin=60)

    styles = getSampleStyleSheet()
    story  = []

    # Title style
    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'],
        fontSize=20, textColor=colors.HexColor('#0f172a'),
        spaceAfter=6, alignment=TA_CENTER, fontName='Helvetica-Bold')
    sub_style = ParagraphStyle('Sub', parent=styles['Normal'],
        fontSize=11, textColor=colors.HexColor('#64748b'),
        spaceAfter=20, alignment=TA_CENTER)
    section_style = ParagraphStyle('Section', parent=styles['Normal'],
        fontSize=13, textColor=colors.HexColor('#1e40af'),
        spaceBefore=16, spaceAfter=8, fontName='Helvetica-Bold')
    body_style = ParagraphStyle('Body', parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#334155'),
        spaceAfter=6, leading=16, alignment=TA_JUSTIFY)
    label_style = ParagraphStyle('Label', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor('#64748b'), fontName='Helvetica-Bold')
    value_style = ParagraphStyle('Value', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor('#0f172a'))

    # Header
    story.append(Paragraph('HYBRID INTRUSION DETECTION SYSTEM', title_style))
    story.append(Paragraph('Network Security Analysis Report', sub_style))
    story.append(HRFlowable(width='100%', thickness=2, color=colors.HexColor('#1e40af')))
    story.append(Spacer(1, 0.15*inch))

    # Meta table
    meta_data = [
        ['Report ID:', f'#{pred["id"]}',   'Generated:', pred['timestamp']],
        ['Analyst:', pred['username'],      'Severity:', rec['severity'].upper()],
        ['Detection Method:', pred['detection_method'], 'Confidence:', f'{pred["confidence"]:.1f}%'],
    ]
    meta_table = Table(meta_data, colWidths=[1.2*inch, 2.0*inch, 1.2*inch, 2.0*inch])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME', (2,0), (2,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#64748b')),
        ('TEXTCOLOR', (2,0), (2,-1), colors.HexColor('#64748b')),
        ('TEXTCOLOR', (1,0), (1,-1), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (3,0), (3,-1), colors.HexColor('#0f172a')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.1*inch))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#e2e8f0')))

    # Detection result
    story.append(Paragraph('Detection Result', section_style))
    sev_color = colors.HexColor(rec['color'])
    result_data = [
        [Paragraph(f'<b>Threat Classification:</b>', label_style),
         Paragraph(f'<b>{pred["prediction"]}</b>', ParagraphStyle('Bold', parent=styles['Normal'],
             fontSize=14, textColor=sev_color, fontName='Helvetica-Bold'))],
        [Paragraph('<b>Alert Title:</b>', label_style),
         Paragraph(rec['title'], value_style)],
    ]
    rt = Table(result_data, colWidths=[2*inch, 4.5*inch])
    rt.setStyle(TableStyle([('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]))
    story.append(rt)

    # Features
    story.append(Paragraph('Network Flow Features', section_style))
    feat_rows = [['Feature', 'Value', 'Feature', 'Value']]
    feat_items = list(features.items())
    for i in range(0, len(feat_items), 2):
        row_data = [feat_items[i][0].replace('_s', '/s'), f'{feat_items[i][1]:,.4f}', '', '']
        if i+1 < len(feat_items):
            row_data[2] = feat_items[i+1][0].replace('_s', '/s')
            row_data[3] = f'{feat_items[i+1][1]:,.4f}'
        feat_rows.append(row_data)

    ft = Table(feat_rows, colWidths=[1.8*inch, 1.5*inch, 1.8*inch, 1.5*inch])
    ft.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(ft)

    # Recommendation
    story.append(Paragraph('Security Recommendation', section_style))
    story.append(Paragraph(rec['text'], body_style))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph('Immediate Action Items:', ParagraphStyle('StepHead', parent=styles['Normal'],
        fontSize=10, fontName='Helvetica-Bold', textColor=colors.HexColor('#0f172a'), spaceAfter=4)))
    for idx, step in enumerate(rec['steps'], 1):
        story.append(Paragraph(f'{idx}. {step}', body_style))

    # Footer
    story.append(Spacer(1, 0.2*inch))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1, 0.05*inch))
    story.append(Paragraph(
        'This report was automatically generated by the Hybrid IDS. For security queries, contact your network security team.',
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                       textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER)))

    doc.build(story)
    buffer.seek(0)
    filename = f'IDS_Report_{pred_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    return send_file(buffer, as_attachment=True, download_name=filename,
                     mimetype='application/pdf')

@app.route('/delete_prediction/<int:pred_id>', methods=['POST'])
@login_required
def delete_prediction(pred_id):
    db = get_db()
    db.execute('DELETE FROM predictions WHERE id=? AND user_id=?',
               (pred_id, session['user_id']))
    db.commit()
    db.close()
    flash('Prediction record deleted.', 'success')
    return redirect(url_for('history'))


# ─── Live Capture ─────────────────────────────────────────────────────────────
@app.route('/api/capture_live')
@login_required
def capture_live():
    """Sniff live traffic for 3 seconds with scapy and compute the 12 flow features."""
    import random
    
    # Smart Fallback / Demo Mode for Cloud Deployments
    run_simulated = False
    if not SCAPY_AVAILABLE or os.environ.get("VERCEL"):
        run_simulated = True

    DURATION = 3  # seconds
    packets = []

    if not run_simulated:
        try:
            packets = sniff(timeout=DURATION, store=True)
            if not packets:
                run_simulated = True
        except Exception:
            run_simulated = True

    if run_simulated:
        # Simulate realistic network traffic for Demo Mode
        time.sleep(DURATION - 1.5)  # slight delay for effect
        return jsonify({
            'Flow_Duration':    round(random.uniform(0.1, 1.5), 6),
            'Tot_Fwd_Pkts':     random.randint(20, 80),
            'Tot_Bwd_Pkts':     random.randint(10, 60),
            'Fwd_Pkt_Len_Mean': round(random.uniform(30, 150), 2),
            'Bwd_Pkt_Len_Mean': round(random.uniform(40, 300), 2),
            'Flow_Byts_s':      round(random.uniform(500, 3000), 2),
            'Flow_Pkts_s':      round(random.uniform(20, 150), 2),
            'Flow_IAT_Mean':    round(random.uniform(0.001, 0.05), 6),
            'Fwd_Header_Len':   random.randint(400, 1600),
            'Bwd_Header_Len':   random.randint(200, 1200),
            'Flow_Flags':       random.choice([0, 4, 5]),
            'Protocol':         random.choice([6, 17]),
            'packets_captured': random.randint(50, 150)
        })

    # ── Compute flow features ──────────────────────────────────────────────────
    fwd_pkts, bwd_pkts = [], []
    fwd_lengths, bwd_lengths = [], []
    fwd_header_total, bwd_header_total = 0, 0
    timestamps = []
    flags_list = []
    protocols = []
    total_bytes = 0

    # Use first packet src as the "forward" direction
    first_ip = None
    for pkt in packets:
        if IP in pkt:
            first_ip = pkt[IP].src
            break

    for pkt in packets:
        if IP not in pkt:
            continue
        ts = float(pkt.time)
        timestamps.append(ts)
        protocols.append(pkt[IP].proto)
        pkt_len = len(pkt)
        total_bytes += pkt_len

        is_fwd = (pkt[IP].src == first_ip)

        # Header length
        ip_header = pkt[IP].ihl * 4 if hasattr(pkt[IP], 'ihl') else 20
        transport_header = 0
        if TCP in pkt:
            transport_header = pkt[TCP].dataofs * 4 if hasattr(pkt[TCP], 'dataofs') else 20
            flags_list.append(int(pkt[TCP].flags))
        elif UDP in pkt:
            transport_header = 8
        header_len = ip_header + transport_header

        if is_fwd:
            fwd_pkts.append(pkt_len)
            fwd_lengths.append(pkt_len)
            fwd_header_total += header_len
        else:
            bwd_pkts.append(pkt_len)
            bwd_lengths.append(pkt_len)
            bwd_header_total += header_len

    tot_fwd = len(fwd_pkts)
    tot_bwd = len(bwd_pkts)
    total_pkts = tot_fwd + tot_bwd

    if len(timestamps) >= 2:
        flow_duration = round(max(timestamps) - min(timestamps), 6)
    else:
        flow_duration = DURATION

    flow_bytes_s  = round(total_bytes / flow_duration, 4) if flow_duration > 0 else 0
    flow_pkts_s   = round(total_pkts / flow_duration, 4) if flow_duration > 0 else 0

    iats = []
    timestamps_sorted = sorted(timestamps)
    for i in range(1, len(timestamps_sorted)):
        iats.append(timestamps_sorted[i] - timestamps_sorted[i-1])
    flow_iat_mean = round(float(np.mean(iats)), 8) if iats else 0.0

    fwd_mean = round(float(np.mean(fwd_lengths)), 4) if fwd_lengths else 0.0
    bwd_mean = round(float(np.mean(bwd_lengths)), 4) if bwd_lengths else 0.0

    # Most common flag & protocol
    dominant_flag = int(max(set(flags_list), key=flags_list.count)) if flags_list else 0
    # Clamp to 0–6 dropdown range
    if dominant_flag > 6: dominant_flag = 4
    dominant_proto = int(max(set(protocols), key=protocols.count)) if protocols else 6
    if dominant_proto not in [1, 6, 17]: dominant_proto = 0

    features = {
        'Flow_Duration':    flow_duration,
        'Tot_Fwd_Pkts':     tot_fwd,
        'Tot_Bwd_Pkts':     tot_bwd,
        'Fwd_Pkt_Len_Mean': fwd_mean,
        'Bwd_Pkt_Len_Mean': bwd_mean,
        'Flow_Byts_s':      flow_bytes_s,
        'Flow_Pkts_s':      flow_pkts_s,
        'Flow_IAT_Mean':    flow_iat_mean,
        'Fwd_Header_Len':   fwd_header_total,
        'Bwd_Header_Len':   bwd_header_total,
        'Flow_Flags':       dominant_flag,
        'Protocol':         dominant_proto,
        'packets_captured': total_pkts,
    }
    return jsonify(features)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
