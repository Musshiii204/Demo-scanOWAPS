import requests
import re
import json
from datetime import datetime
import smtplib
from email.message import EmailMessage

with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

headers = {'User-Agent': 'Mozilla/5.0'}

def log_result(log, text):
    print(text)
    log.append(text)

def scan_sql_injection(url, log):
    try:
        res = requests.get(url + "' OR '1'='1", headers=headers)
        if "sql" in res.text.lower() or "syntax" in res.text.lower():
            log_result(log, "[!] SQL Injection: Có thể bị lỗi injection.")
        else:
            log_result(log, "[+] SQL Injection: Không phát hiện lỗi.")
    except:
        log_result(log, "[-] Không kiểm tra được SQLi.")

def scan_xss(url, log):
    try:
        xss = "<script>alert('xss')</script>"
        res = requests.get(url + "?q=" + xss, headers=headers)
        if xss in res.text:
            log_result(log, "[!] XSS: Payload phản hồi trong nội dung.")
        else:
            log_result(log, "[+] XSS: Không phát hiện lỗi.")
    except:
        log_result(log, "[-] Không kiểm tra được XSS.")

def check_server_info(url, log):
    try:
        res = requests.get(url, headers=headers)
        server = res.headers.get('Server')
        if server:
            log_result(log, f"[!] Lộ thông tin Server: {server}")
        else:
            log_result(log, "[+] Không lộ thông tin Server.")
    except:
        log_result(log, "[-] Không kiểm tra được Header.")

def check_sensitive_info(url, log):
    try:
        res = requests.get(url, headers=headers)
        if re.search(r'(?i)password|admin|secret|apikey|token', res.text):
            log_result(log, "[!] Phát hiện từ khóa nhạy cảm trong nội dung!")
        else:
            log_result(log, "[+] Không phát hiện dữ liệu nhạy cảm.")
    except:
        log_result(log, "[-] Không kiểm tra được nội dung.")

def check_common_files(url, log):
    paths = ['.env', '.git/config', 'config.php', 'debug.log']
    found = False
    for path in paths:
        try:
            full = url.rstrip('/') + '/' + path
            res = requests.get(full, headers=headers)
            if res.status_code == 200 and len(res.text.strip()) > 10:
                log_result(log, f"[!] File nhạy cảm tồn tại: {full}")
                found = True
        except:
            continue
    if not found:
        log_result(log, "[+] Không phát hiện file nhạy cảm.")

def check_js_libs(url, log):
    try:
        res = requests.get(url, headers=headers)
        scripts = re.findall(r'<script[^>]+src=["\\\'](.*?)["\\\']', res.text)
        found = False
        for s in scripts:
            if any(lib in s for lib in ['jquery', 'bootstrap', 'vue', 'react']):
                log_result(log, f"[!] JS có thể cũ: {s}")
                found = True
        if not found:
            log_result(log, "[+] Không phát hiện thư viện JS lỗi thời.")
    except:
        log_result(log, "[-] Không kiểm tra được JS lib.")

def check_headers(url, log):
    try:
        res = requests.get(url, headers=headers)
        security = ['X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy']
        for h in security:
            if h not in res.headers:
                log_result(log, f"[!] Thiếu header bảo mật: {h}")
        if all(h in res.headers for h in security):
            log_result(log, "[+] Các header bảo mật đầy đủ.")
    except:
        log_result(log, "[-] Không kiểm tra được Header.")

def check_ssrf(url, log):
    try:
        payload = "http://127.0.0.1:80"
        res = requests.get(url + "?url=" + payload, headers=headers, timeout=5)
        if "localhost" in res.text.lower() or "127.0.0.1" in res.text:
            log_result(log, "[!] Có thể tồn tại SSRF.")
        else:
            log_result(log, "[+] Không phát hiện SSRF.")
    except:
        log_result(log, "[+] Không phản hồi SSRF.")

def check_auth(url, log):
    paths = ['admin', 'login', 'user/login']
    found = False
    for p in paths:
        try:
            full = url.rstrip('/') + '/' + p
            res = requests.get(full, headers=headers)
            if res.status_code == 200 and 'password' in res.text.lower():
                log_result(log, f"[!] Trang đăng nhập phát hiện: {full}")
                found = True
        except:
            continue
    if not found:
        log_result(log, "[+] Không phát hiện login point.")

def send_email_report(filepath):
    if not config.get("email_enabled"): return
    try:
        msg = EmailMessage()
        msg["Subject"] = "OWASP Scan Report"
        msg["From"] = config["email_from"]
        msg["To"] = config["email_to"]
        msg.set_content("Gửi Chủ Nhân, đây là báo cáo OWASP.")

        with open(filepath, "rb") as f:
            msg.add_attachment(f.read(), maintype="text", subtype="plain", filename="owasp_report.txt")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(config["email_from"], config["email_app_password"])
            smtp.send_message(msg)
        print("📩 Đã gửi báo cáo qua Email.")
    except Exception as e:
        print("❌ Gửi email thất bại:", e)

def send_telegram_report(filepath):
    if not config.get("telegram_enabled"): return
    try:
        url = f"https://api.telegram.org/bot{config['telegram_bot_token']}/sendDocument"
        with open(filepath, "rb") as file:
            res = requests.post(url, data={"chat_id": config["telegram_chat_id"]}, files={"document": file})
        if res.status_code == 200:
            print("📲 Đã gửi báo cáo qua Telegram.")
        else:
            print("❌ Gửi telegram thất bại:", res.text)
    except Exception as e:
        print("❌ Telegram lỗi:", e)

def run_all_scans(url):
    log = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_result(log, f"=== OWASP Top 10 Scan – {now} ===")
    log_result(log, f"Target: {url}\n")


    scan_sql_injection(url, log)
    scan_xss(url, log)
    check_server_info(url, log)
    check_sensitive_info(url, log)
    check_common_files(url, log)
    check_js_libs(url, log)
    check_headers(url, log)
    check_ssrf(url, log)
    check_auth(url, log)

    with open("owasp_report.txt", "w", encoding="utf-8") as f:
        for line in log:
            f.write(line + "\n")
    print("\n✅ Đã lưu vào owasp_report.txt")

    send_email_report("owasp_report.txt")
    send_telegram_report("owasp_report.txt")

if __name__ == "__main__":
    print("=== OWASP Top 10 Scanner - Gửi báo cáo tự động ===")
    target = input("Nhập URL website (https://apectech.net): ").strip()
    if not target.startswith("http"):
        target = "http://" + target
    run_all_scans(target)
