import http.client
import json
import time
from port import extract_honeypot_port
from extract_ips import extract_snort_ip, extract_apache_ip

class StaticFlowPusher(object):
  
    def __init__(self, server):
        self.server = server
  
    def get(self, data):
        ret = self.rest_call({}, 'GET')
        return json.loads(ret[2])
  
    def set(self, data):
        ret = self.rest_call(data, 'POST')
        return ret[0] == 200
  
    def remove(self, objtype, data):
        ret = self.rest_call(data, 'DELETE')
        return ret[0] == 200
  
    def rest_call(self, data, action):
        path = '/wm/staticflowpusher/json'
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            }
        body = json.dumps(data)
        conn = http.client.HTTPConnection(self.server, 8080)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        print (ret)
        conn.close()
        return ret
    
controller_ip="192.168.100.40"
pusher = StaticFlowPusher(controller_ip)
honeypot_ip="192.168.100.20"
output_port= extract_honeypot_port(controller_ip,honeypot_ip)

  
#alert_file_path = '/var/log/snort/alert'
snort_logs = 'alert.txt'
apache_logs= 'access.log'
last_src_ip = None

snort_log_last_position = 0
apache_log_last_position = 0
name = 1

while True:
    
    try:
        with open(snort_logs, 'r') as file:
            
            file.seek(snort_log_last_position)
            
            for alert in file:
            
                alert_src_ip, alert_dest_ip = extract_snort_ip(alert)
                
                if alert_src_ip!= None and alert_dest_ip != last_src_ip and alert_src_ip != last_src_ip and alert_src_ip != controller_ip and alert_src_ip != honeypot_ip:
                
                    last_src_ip = alert_src_ip
                    print(f"AlERT SOURCE IP : {last_src_ip}")
                    
                    # Define the flow rule to match the alert source IP and send to LAN2
                    flow_rule = {
                    'switch':"00:00:2a:09:74:dd:62:4e",
                    "name":name,
                    "cookie":"0",
                    "priority":"3000",
                    "eth_type": "0x800",  # IPv4
                    "ipv4_src": last_src_ip,
                    "ipv4_dst": "0.0.0.0/0",
                    "active":"true",
                    "actions":f"output={output_port}"
                    }
                    pusher.set(flow_rule)
                    name +=1
                        
            snort_log_last_position = file.tell()
            
        with open(apache_logs,'r') as file:
            
            file.seek(apache_log_last_position)
            
            for alert in file:
            
                apache_src_ip = extract_apache_ip(alert)
                
                if apache_src_ip != None and apache_src_ip != controller_ip :
                    
                    print(f"AlERT SOURCE IP : {apache_src_ip}")
                    
                    # Define the flow rule to match the alert source IP and send to LAN2
                    flow_rule = {
                    'switch':"00:00:2a:09:74:dd:62:4e",
                    "name":name,
                    "cookie":"0",
                    "priority":"3000",
                    "eth_type": "0x800",  # IPv4
                    "ipv4_src": apache_src_ip,
                    #"ipv4_dst": "0.0.0.0/0",
                    #"set_ipv4_dst":"192.168.100.20",
                    "active":"true",
                    "actions":f"output={output_port}"

                    }
                    pusher.set(flow_rule)
                    name +=1
                        
            apache_log_last_position= file.tell()
            
                    
    except Exception as e:
        print(f"Error reading Snort alert file: {str(e)}")

    time.sleep(1)
