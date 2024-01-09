import requests

def extract_honeypot_port(controller_ip,honeypot_ip):

    url= f"http://{controller_ip}:8080/wm/device/?ipv4={honeypot_ip}"
    response= requests.get(url)
    if response.status_code == 200:
        data=response.json()
        devices=data.get("devices",[])
        attachment_point=devices[0]["attachmentPoint"]
        port_number= attachment_point[0]["port"]
        print(f"HONEYPOT PORT NUMBER: {port_number}")
        return port_number
    else:
        print("ERROR 404")
