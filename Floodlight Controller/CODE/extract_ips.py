import re

def extract_snort_ip(alert_line):
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)? -> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?'
    match = re.search(ip_pattern, alert_line)
    if match:
        #        print (f"Snort Source IP:{match.group(1)}")
        return match.group(1), match.group(2)
    else:
        return None, None
 
    
def extract_Modsec_ip(line):
    # Define a regular expression pattern to match the client IP and port number
    pattern = r"\[client (\d+\.\d+\.\d+\.\d+):(\d+)\]"

    # Initialize variables to store client IP and port number
    client_ip = None
    port_number = None
    # Use re.search to find the pattern in the log entry
    match = re.search(pattern, line)

    # Extract client IP and port number if a match is found
    if match:
        client_ip = match.group(1)
        port_number = match.group(2)
    else:
        print("No match found in log entry:", line)

    # Return client IP and port number as variables
    return client_ip, port_number
