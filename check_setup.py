import flask
import nmap
import requests

try:
    nm = nmap.PortScanner()
    print("✅ Environment is ready!")
    print(f"Flask version: {flask.__version__}")
except Exception as e:
    print(f"❌ Setup error: {e}")
