import re
from urllib.parse import urlparse

def analyze_url(url):
    print("==================================================")
    print("  DIGITAL THREATS ATTACK INVESTIGATION TOOL v1.0")
    print("==================================================")
    print(f"\n[+] Running Digital Threat Investigation on: {url}\n")
    
    threat_score = 0
    findings = []
    
    # Check 1: Scheme (HTTP vs HTTPS)
    parsed_url = urlparse(url)
    if parsed_url.scheme != 'https':
        threat_score += 25
        findings.append("[RISK] Connection is NOT secure (Uses HTTP instead of HTTPS)")
    
    # Check 2: Raw IP Address usage
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    hostname = parsed_url.hostname if parsed_url.hostname else ''
    if re.match(ip_pattern, hostname):
        threat_score += 40
        findings.append("[HIGH RISK] Uses raw IP address instead of domain name (Common Phishing Tactic)")
        
    # Check 3: Suspicious Keywords
    suspicious_keywords = ['login', 'verify', 'update', 'account', 'banking', 'secure', 'pay', 'paypal']
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            threat_score += 15
            findings.append(f"[WARNING] Suspicious keyword detected: '{keyword}'")
            
    # Print Results
    print("----- INVESTIGATION RESULTS -----")
    for finding in findings:
        print(finding)
        
    print(f"\nOverall Threat Score: {threat_score}/100")
    if threat_score >= 50:
        print("FINAL ASSESSMENT: 🚨 HIGH RISK PHISHING / MALICIOUS THREAT DETECTED!")
    else:
        print("FINAL ASSESSMENT: ✅ LOW RISK / POTENTIALLY SAFE")
        
    # Save Report
    report_content = f"URL: {url}\nThreat Score: {threat_score}/100\nFindings:\n" + "\n".join(findings) + "\n\n"
    with open("threat_investigation_report.txt", "a") as f:
        f.write(report_content)
        
    print("\n[+] Full Investigation Report saved to 'threat_investigation_report.txt'")

if __name__ == "__main__":
    target_url = input("Enter Suspicious URL to Investigate: ")
    analyze_url(target_url)
  
