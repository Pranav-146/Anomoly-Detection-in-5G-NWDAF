import hmac
import hashlib

# Paste the challenge string from the monitor page
challenge_hex = "47d6b53a15896c76601aec4c7742dd76"
secret_key = b"subscriber_shared_secret_001"

token = hmac.new(secret_key, bytes.fromhex(challenge_hex), hashlib.sha256).hexdigest()
print(token)
# 1e8b473d840301e6a8348c60d30eee48