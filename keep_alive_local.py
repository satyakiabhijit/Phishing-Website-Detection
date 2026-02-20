#!/usr/bin/env python3
"""
PhishGuard Keep-Alive Script
Pings your Streamlit app every 14 minutes to prevent it from sleeping.
Run this on your local machine or server if you prefer not to use GitHub Actions.
"""

import requests
import time
from datetime import datetime
import sys

# ── Configuration ────────────────────────────────────────────────────────────
APP_URL = "https://your-app-name.streamlit.app"  # Replace with your Streamlit URL
INTERVAL = 840  # 14 minutes in seconds (Streamlit sleeps after ~15 min)
TIMEOUT = 30    # Request timeout in seconds

# ── Color codes for terminal output ──────────────────────────────────────────
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def ping_app():
    """Send a GET request to the Streamlit app"""
    try:
        response = requests.get(APP_URL, timeout=TIMEOUT)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if response.status_code == 200:
            print(f"{GREEN}✓{RESET} [{timestamp}] App is alive! Status: {response.status_code}")
            return True
        else:
            print(f"{YELLOW}⚠{RESET} [{timestamp}] Unexpected status: {response.status_code}")
            return False
            
    except requests.Timeout:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{RED}✗{RESET} [{timestamp}] Request timeout after {TIMEOUT}s")
        return False
        
    except requests.RequestException as e:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{RED}✗{RESET} [{timestamp}] Error: {e}")
        return False

def main():
    """Main keep-alive loop"""
    # Validate URL
    if "your-app-name" in APP_URL:
        print(f"{RED}ERROR:{RESET} Please update APP_URL with your actual Streamlit URL!")
        print(f"Edit line 13 in this script and replace with your app URL.")
        sys.exit(1)
    
    print(f"{BLUE}╔════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BLUE}║{RESET}     PhishGuard Keep-Alive Script Started          {BLUE}║{RESET}")
    print(f"{BLUE}╚════════════════════════════════════════════════════════╝{RESET}")
    print(f"\n📍 Target: {APP_URL}")
    print(f"⏱️  Interval: {INTERVAL//60} minutes")
    print(f"🔄 Press Ctrl+C to stop\n")
    
    ping_count = 0
    success_count = 0
    
    try:
        while True:
            ping_count += 1
            print(f"{BLUE}[Ping #{ping_count}]{RESET} ", end="")
            
            if ping_app():
                success_count += 1
            
            # Show stats every 10 pings
            if ping_count % 10 == 0:
                success_rate = (success_count / ping_count) * 100
                print(f"\n{BLUE}📊 Stats:{RESET} {success_count}/{ping_count} successful ({success_rate:.1f}%)\n")
            
            # Wait for next ping
            time.sleep(INTERVAL)
            
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}⚠{RESET} Keep-alive script stopped by user.")
        print(f"{BLUE}📊 Final Stats:{RESET} {success_count}/{ping_count} successful pings")
        sys.exit(0)

if __name__ == "__main__":
    main()
