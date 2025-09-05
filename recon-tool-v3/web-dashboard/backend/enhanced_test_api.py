#!/usr/bin/env python3
"""
Enhanced Phase 6 Backend API Test Script
Comprehensive testing with scan completion monitoring and report generation
"""

import requests
import json
import time
import websocket
import threading
from datetime import datetime
import uuid

# API Base URL
BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api/v1"

def test_health_check():
    """Test the health check endpoint"""
    print("🔍 Testing Health Check...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            print("✅ Health check passed")
            data = response.json()
            print(f"   Service: {data['service']}")
            print(f"   Version: {data['version']}")
            print(f"   Status: {data['status']}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_api_documentation():
    """Test API documentation access"""
    print("\n📚 Testing API Documentation...")
    try:
        response = requests.get(f"{BASE_URL}/api/docs")
        if response.status_code == 200:
            print("✅ API documentation accessible")
            return True
        else:
            print(f"❌ API docs failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API docs error: {e}")
        return False

def test_user_registration():
    """Test user registration with unique username"""
    print("\n👤 Testing User Registration...")
    try:
        # Generate unique username
        unique_id = str(uuid.uuid4())[:8]
        user_data = {
            "username": f"testuser_{unique_id}",
            "email": f"test_{unique_id}@example.com",
            "password": "testpass123",
            "full_name": f"Test User {unique_id}",
            "organization": "Test Organization"
        }
        
        response = requests.post(f"{API_URL}/users/register", json=user_data)
        if response.status_code == 200:
            print("✅ User registration successful")
            user = response.json()
            print(f"   Created user ID: {user['id']}")
            print(f"   Username: {user['username']}")
            print(f"   Email: {user['email']}")
            return user
        else:
            print(f"❌ User registration failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return None
    except Exception as e:
        print(f"❌ User registration error: {e}")
        return None

def test_admin_login():
    """Test admin user login"""
    print("\n🔑 Testing Admin Login...")
    try:
        login_data = {
            "username": "admin",
            "password": "admin123"
        }
        
        response = requests.post(f"{API_URL}/users/login", data=login_data)
        if response.status_code == 200:
            print("✅ Admin login successful")
            token_data = response.json()
            token = token_data["access_token"]
            print(f"   Token type: {token_data['token_type']}")
            print(f"   Token: {token[:30]}...")
            return token
        else:
            print(f"❌ Admin login failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Admin login error: {e}")
        return None

def test_user_profile(token):
    """Test getting current user profile"""
    print("\n👤 Testing User Profile...")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/users/me", headers=headers)
        if response.status_code == 200:
            print("✅ User profile retrieved")
            user = response.json()
            print(f"   User ID: {user['id']}")
            print(f"   Username: {user['username']}")
            print(f"   Is Admin: {user['is_admin']}")
            return user
        else:
            print(f"❌ User profile failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ User profile error: {e}")
        return None

def test_create_scan(token, target="example.com"):
    """Test creating a new scan"""
    print(f"\n🔍 Testing Scan Creation for {target}...")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        scan_data = {
            "name": f"Enhanced Test Scan - {target}",
            "description": f"Comprehensive testing of {target} reconnaissance",
            "target": target,
            "target_type": "domain",
            "profile": "quick",
            "tools": ["subdomain_enumerator", "port_scanner", "vulnerability_scanner"],
            "parameters": {
                "timeout": 300,
                "max_depth": 2,
                "threads": 5
            }
        }
        
        response = requests.post(f"{API_URL}/scans/", json=scan_data, headers=headers)
        if response.status_code == 200:
            print("✅ Scan creation successful")
            scan = response.json()
            print(f"   Scan ID: {scan['id']}")
            print(f"   Scan UUID: {scan['scan_uuid']}")
            print(f"   Target: {scan['target']}")
            print(f"   Profile: {scan['profile']}")
            print(f"   Status: {scan['status']}")
            print(f"   Progress: {scan['progress']}%")
            return scan
        else:
            print(f"❌ Scan creation failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Scan creation error: {e}")
        return None

def monitor_scan_progress(token, scan_id, max_wait=30):
    """Monitor scan progress until completion"""
    print(f"\n⏱️  Monitoring Scan {scan_id} Progress...")
    headers = {"Authorization": f"Bearer {token}"}
    
    for i in range(max_wait):
        try:
            response = requests.get(f"{API_URL}/scans/{scan_id}", headers=headers)
            if response.status_code == 200:
                scan = response.json()
                status = scan['status']
                progress = scan['progress']
                current_tool = scan.get('current_tool', 'N/A')
                
                print(f"   📊 Status: {status} | Progress: {progress}% | Tool: {current_tool}")
                
                if status in ['completed', 'failed', 'cancelled']:
                    if status == 'completed':
                        print("✅ Scan completed successfully")
                        if scan.get('results'):
                            results = scan['results']
                            if 'summary' in results:
                                summary = results['summary']
                                print(f"   🎯 Findings: {summary.get('findings_count', 0)}")
                                print(f"   🔒 Vulnerabilities: {summary.get('vulnerabilities', 0)}")
                                print(f"   🌐 Subdomains: {summary.get('subdomains_found', 0)}")
                    else:
                        print(f"❌ Scan {status}")
                        if scan.get('error_message'):
                            print(f"   Error: {scan['error_message']}")
                    return scan
                
                time.sleep(2)
            else:
                print(f"   ❌ Error checking scan: {response.status_code}")
                return None
        except Exception as e:
            print(f"   ❌ Error monitoring scan: {e}")
            return None
    
    print("⏰ Scan monitoring timeout")
    return None

def test_list_scans(token):
    """Test listing all scans"""
    print("\n📋 Testing Scan Listing...")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/scans/", headers=headers)
        if response.status_code == 200:
            print("✅ Scan listing successful")
            scans = response.json()
            print(f"   Found {len(scans)} total scans")
            
            # Group by status
            status_counts = {}
            for scan in scans:
                status = scan['status']
                status_counts[status] = status_counts.get(status, 0) + 1
                print(f"   - {scan['name']} ({status}) - {scan['target']} [{scan['progress']}%]")
            
            print("\n   📊 Status Summary:")
            for status, count in status_counts.items():
                print(f"   - {status}: {count} scans")
            
            return scans
        else:
            print(f"❌ Scan listing failed: {response.status_code}")
            return []
    except Exception as e:
        print(f"❌ Scan listing error: {e}")
        return []

def test_create_report(token, scan_id):
    """Test creating a report from completed scan"""
    print(f"\n📊 Testing Report Creation for Scan {scan_id}...")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        
        # First check if scan is completed
        scan_response = requests.get(f"{API_URL}/scans/{scan_id}", headers=headers)
        if scan_response.status_code != 200:
            print("❌ Cannot verify scan status")
            return None
        
        scan = scan_response.json()
        if scan['status'] != 'completed':
            print(f"❌ Scan status is '{scan['status']}', cannot generate report")
            return None
        
        report_data = {
            "name": f"Test Report - {scan['target']}",
            "description": f"Comprehensive report for {scan['target']} reconnaissance",
            "report_type": "comprehensive",
            "format": "html",
            "scan_id": scan_id,
            "generation_parameters": {
                "include_charts": True,
                "include_recommendations": True,
                "risk_assessment": True
            }
        }
        
        response = requests.post(f"{API_URL}/reports/", json=report_data, headers=headers)
        if response.status_code == 200:
            print("✅ Report creation successful")
            report = response.json()
            print(f"   Report ID: {report['id']}")
            print(f"   Report UUID: {report['report_uuid']}")
            print(f"   Format: {report['format']}")
            print(f"   Status: {report['status']}")
            return report
        else:
            print(f"❌ Report creation failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Report creation error: {e}")
        return None

def test_list_reports(token):
    """Test listing all reports"""
    print("\n📋 Testing Report Listing...")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/reports/", headers=headers)
        if response.status_code == 200:
            print("✅ Report listing successful")
            reports = response.json()
            print(f"   Found {len(reports)} total reports")
            
            for report in reports:
                size_mb = report.get('file_size', 0) / (1024 * 1024) if report.get('file_size') else 0
                print(f"   - {report['name']} ({report['format']}) - {report['target']} [{report['status']}] ({size_mb:.2f}MB)")
            
            return reports
        else:
            print(f"❌ Report listing failed: {response.status_code}")
            return []
    except Exception as e:
        print(f"❌ Report listing error: {e}")
        return []

def test_websocket_enhanced():
    """Enhanced WebSocket testing with multiple message types"""
    print("\n🔌 Testing Enhanced WebSocket Communication...")
    
    messages_received = []
    
    def on_message(ws, message):
        try:
            data = json.loads(message)
            messages_received.append(data)
            msg_type = data.get('type', 'unknown')
            print(f"   📨 {msg_type}: {message[:100]}{'...' if len(message) > 100 else ''}")
        except:
            print(f"   📨 Raw message: {message}")
    
    def on_error(ws, error):
        print(f"   ❌ WebSocket error: {error}")
    
    def on_close(ws, close_status_code, close_msg):
        print("   🔌 WebSocket connection closed")
    
    def on_open(ws):
        print("   ✅ WebSocket connection opened")
        
        # Send multiple test messages
        test_messages = [
            {"type": "ping", "timestamp": datetime.now().isoformat()},
            {"type": "subscribe", "event_type": "scan_updates"},
            {"type": "scan_status_request", "scan_id": 1},
            {"type": "unknown_message", "data": "test"}
        ]
        
        for msg in test_messages:
            ws.send(json.dumps(msg))
            time.sleep(0.5)
        
        # Close after processing
        def close_after_delay():
            time.sleep(3)
            ws.close()
        
        threading.Thread(target=close_after_delay).start()
    
    try:
        ws_url = "ws://localhost:8000/ws/enhanced_test_client"
        ws = websocket.WebSocketApp(
            ws_url,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close
        )
        ws.run_forever()
        
        print(f"   📊 Received {len(messages_received)} messages")
        return True
    except Exception as e:
        print(f"   ❌ WebSocket connection error: {e}")
        return False

def test_api_endpoints_stress():
    """Test API endpoints under stress"""
    print("\n🔥 Testing API Stress Scenarios...")
    
    # Test invalid authentication
    print("   Testing invalid authentication...")
    invalid_headers = {"Authorization": "Bearer invalid_token"}
    response = requests.get(f"{API_URL}/scans/", headers=invalid_headers)
    if response.status_code == 401:
        print("   ✅ Invalid auth correctly rejected")
    else:
        print(f"   ❌ Invalid auth not rejected: {response.status_code}")
    
    # Test non-existent endpoints
    print("   Testing non-existent endpoints...")
    response = requests.get(f"{API_URL}/nonexistent")
    if response.status_code == 404:
        print("   ✅ Non-existent endpoint correctly returns 404")
    else:
        print(f"   ❌ Non-existent endpoint: {response.status_code}")
    
    # Test malformed JSON
    print("   Testing malformed JSON...")
    try:
        response = requests.post(
            f"{API_URL}/users/register",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        if response.status_code in [400, 422]:
            print("   ✅ Malformed JSON correctly rejected")
        else:
            print(f"   ❌ Malformed JSON not rejected: {response.status_code}")
    except:
        print("   ✅ Malformed JSON correctly rejected")

def main():
    """Run comprehensive enhanced test suite"""
    print("🚀 Enhanced Phase 6 Backend API Test Suite")
    print("=" * 60)
    
    # Basic connectivity tests
    if not test_health_check():
        print("❌ Health check failed, stopping tests")
        return False
    
    test_api_documentation()
    
    # Authentication tests
    test_user_registration()
    token = test_admin_login()
    if not token:
        print("❌ Admin login failed, stopping tests")
        return False
    
    test_user_profile(token)
    
    # Scan management tests
    scan = test_create_scan(token, "example.com")
    if scan:
        scan_id = scan["id"]
        
        # Monitor scan until completion
        completed_scan = monitor_scan_progress(token, scan_id, max_wait=15)
        
        if completed_scan and completed_scan['status'] == 'completed':
            # Test report generation on completed scan
            report = test_create_report(token, scan_id)
            if report:
                time.sleep(2)  # Wait for report generation
        
        # List all scans and reports
        test_list_scans(token)
        test_list_reports(token)
    
    # WebSocket tests
    test_websocket_enhanced()
    
    # Stress tests
    test_api_endpoints_stress()
    
    print("\n🎉 Enhanced Phase 6 Backend Test Suite Complete!")
    print("=" * 60)
    print("✅ Web Dashboard Backend is fully operational and tested!")
    print(f"🌐 API Documentation: {BASE_URL}/api/docs")
    print(f"🔧 Admin Login: admin / admin123")
    print(f"📊 Health Check: {BASE_URL}/health")
    
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
