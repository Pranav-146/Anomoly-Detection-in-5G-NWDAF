import hashlib
import hmac

# Paste the challenge string from the monitor page.
challenge_hex = "21004eadb27c46fbdef34b12b3714244"
secret_key = b"subscriber_shared_secret_001"

token = hmac.new(secret_key, bytes.fromhex(challenge_hex), hashlib.sha256).hexdigest()
print(token)