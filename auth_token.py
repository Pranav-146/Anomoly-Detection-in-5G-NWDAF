import hashlib
import hmac

# Paste the challenge string from the monitor page.
challenge_hex = "606b7a005e1de9d83d16fc269ad49351"
secret_key = b"subscriber_shared_secret_001"

token = hmac.new(secret_key, bytes.fromhex(challenge_hex), hashlib.sha256).hexdigest()
print(token)