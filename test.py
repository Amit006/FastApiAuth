import requests
import os

BASE_URL = "http://localhost:8000"

def test_authentication_flow():
    # Login
    login_response = requests.post(
        f"{BASE_URL}/login",
        data={"username": "johndoe", "password": "secret"},
        headers={"User-Agent": "TestDevice/1.0"}
    )
    
    if login_response.status_code != 200:
        print("Login failed!")
        return
    
    token = login_response.json()["access_token"]
    print("Login successful! Token:", token[:50] + "...")
    
    # Access protected endpoint
    profile_response = requests.get(
        f"{BASE_URL}/profile",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    if profile_response.status_code == 200:
        profile_data = profile_response.json()
        print("\nUser Profile:")
        print(f"Username: {profile_data['username']}")
        print(f"Device ID: {profile_data['device']['id']}")
        print(f"Device Type: {profile_data['device']['type']}")
    else:
        print("Failed to access profile:", profile_response.text)
    
    # Test sensitive action
    sensitive_response = requests.get(
        f"{BASE_URL}/sensitive-action",
        headers={
            "Authorization": f"Bearer {token}",
            "Confirmation": "yes"
        }
    )
    
    if sensitive_response.status_code == 200:
        print("\nSensitive action successful!")
        print(sensitive_response.json())
    else:
        print("\nSensitive action failed:", sensitive_response.text)

if __name__ == "__main__":
    test_authentication_flow()