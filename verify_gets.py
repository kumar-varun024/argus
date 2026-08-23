import requests
import os
import glob

base_url = "http://127.0.0.1:8000"
conv_dir = os.path.expanduser("~/.argus/workspace/conversations")

def count_files():
    return len(glob.glob(os.path.join(conv_dir, "*.json")))

print("Initial count:", count_files())

requests.get(base_url)
print("After GET /:", count_files())

requests.get(f"{base_url}/api/conversations/")
print("After GET /api/conversations/:", count_files())

requests.get(f"{base_url}/api/conversations/search")
print("After GET /api/conversations/search:", count_files())

requests.get(f"{base_url}/?cid=983f9704-962f-4259-b468-16822314bed6")
print("After GET /?cid=...:", count_files())

