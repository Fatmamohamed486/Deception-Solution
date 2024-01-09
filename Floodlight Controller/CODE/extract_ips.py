import re

def extract_snort_ip(alert_line):
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)? -> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?'
    match = re.search(ip_pattern, alert_line)
    if match:
        print (f"Snort Source IP:{match.group(1)}")
        return match.group(1), match.group(2)
    else:
        return None, None
 
    
def extract_apache_ip(log_line):
    pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[.*\] "GET /DVWA/(config|database)'
    match = re.search(pattern, log_line)
    if match:
        #print(f"Apache Source IP: {match.group(1)}")
        return match.group(1)
    else:
        print("No matches found.")
        return None
