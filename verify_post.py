import requests
import os
import glob

base_url = "http://127.0.0.1:8000"
conv_dir = os.path.expanduser("~/.argus/workspace/conversations")

def count_files():
    return len(glob.glob(os.path.join(conv_dir, "*.json")))

c1 = count_files()
# 5. Simulate + Task / Conv button
r_create = requests.post(f"{base_url}/api/conversations/", json={})
cid = r_create.json()["conversation_id"]
c2 = count_files()

print(f"Created conversation: count changed by {c2 - c1}")

# 6. Verify that sending multiple messages in that conversation does NOT create additional conversations.
r_chat1 = requests.post(f"{base_url}/chat/stream", data={"cid": cid, "message": "First message"}, stream=True)
c3 = count_files()
print(f"After message 1: count changed by {c3 - c2}")

r_chat2 = requests.post(f"{base_url}/chat/stream", data={"cid": cid, "message": "Second message"}, stream=True)
c4 = count_files()
print(f"After message 2: count changed by {c4 - c3}")

