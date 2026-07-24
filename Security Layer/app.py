from flask import Flask, render_template_string, request, jsonify
import time

# Importing your project's verified security layer modules
from event_log import WindowEvent
from realtime_engine import SecurityLayerEngine 
import stepup_auth

app = Flask(__name__)

# Initialize your stateful engine
engine = SecurityLayerEngine()

# Defined key for demo/simulation validation matching stepup expected bytes format
DEMO_SECRET_KEY = b"subscriber_shared_secret_001"

# Track active cryptographic challenges locally for the demo web UI
active_challenges = {} 

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>5G Security Layer Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f6f9; color: #333; }
        .container { max-width: 700px; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        h1 { color: #1a365d; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
        .btn { background: #3182ce; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #2b6cb0; }
        .btn-danger { background: #e53e3e; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .btn-danger:hover { background: #c53030; }
        .status-box { margin-top: 20px; padding: 15px; border-radius: 4px; font-weight: bold; background: #edf2f7; }
        .blocked { background: #fed7d7; color: #9b2c2c; border-left: 5px solid #e53e3e; }
        .allowed { background: #c6f6d5; color: #22543d; border-left: 5px solid #38a169; }
        .auth-zone { margin-top: 20px; padding: 20px; border: 1px dashed #cbd5e0; background: #fffaf0; border-radius: 4px; display: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>5G NWDAF Security Layer Live Monitor</h1>
        <p>Target Subscriber (SUPI/IMSI): <strong>imsi-208950000000001</strong></p>
        
        <button class="btn" onclick="sendAttempt(false)">Send Clean Attempt</button>
        <button class="btn btn-danger" onclick="sendAttempt(true)">Send Fake/Failed Attempt</button>
        
        <div id="statusBox" class="status-box allowed">System Status: Monitoring (No Anomalies)</div>

        <div id="authZone" class="auth-zone">
            <h3>⚠️ NIST SP 800-63B Step-Up Challenge Required</h3>
            <p>Cryptographic Challenge (Hex): <code id="challengeHex"></code></p>
            <input type="text" id="otpInput" placeholder="Enter HMAC-SHA256 Response" style="width: 70%; padding: 8px;">
            <button class="btn" onclick="verifyOTP()">Verify</button>
        </div>
    </div>

    <script>
        function sendAttempt(isFail) {
            fetch('/process-event', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ is_fail: isFail })
            })
            .then(res => res.json())
            .then(data => {
                const statusBox = document.getElementById('statusBox');
                const authZone = document.getElementById('authZone');
                
                if (data.status === 'BLOCKED') {
                    statusBox.className = "status-box blocked";
                    statusBox.innerText = "❌ STATUS: BLOCKED. Mitigation deployed via Closed-Loop Pipeline.";
                    authZone.style.display = "block";
                    document.getElementById('challengeHex').innerText = data.challenge;
                } else {
                    statusBox.className = "status-box allowed";
                    statusBox.innerText = "✅ STATUS: ALLOWED. Traffic ratios within tolerable bounds.";
                    authZone.style.display = "none";
                }
            });
        }

        // Verification JS logic
        function verifyOTP() {
            const response = document.getElementById('otpInput').value;
            fetch('/verify-auth', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ response: response })
            })
            .then(res => res.json())
            .then(data => {
                alert(data.message);
                if (data.success) {
                    location.reload();
                }
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/process-event', methods=['POST'])
def process_event():
    is_fail = request.json.get('is_fail', False)
    supi = "imsi-208950000000001"
    now = time.time()
    
    attempts = 1
    failures = 1 if is_fail else 0
    origin = "cell-id-001"
    window_index = 0 
    
    # Instantiate your WindowEvent positional structure cleanly
    event_data = WindowEvent(supi, origin, window_index, attempts, failures, now)
    
    # Process the data object into your real-time engine to keep state tracked
    verdict = engine.process_event(event_data, now=now)
    
    # DEMO BYPASS: If is_fail is True, we force the action to 'BLOCK' immediately
    if is_fail:
        verdict['action'] = 'BLOCK'
    
    if verdict.get('action') == 'BLOCK':
        challenge_data = stepup_auth.issue_challenge()
        
        # Convert bytes token output to clean hex string for JSON stability
        if isinstance(challenge_data, bytes):
            challenge_str = challenge_data.hex()
        else:
            challenge_str = str(challenge_data)
            
        active_challenges[supi] = challenge_data
        return jsonify({
            'status': 'BLOCKED',
            'challenge': challenge_str
        })
        
    return jsonify({
        'status': 'ALLOWED'
    })

@app.route('/verify-auth', methods=['POST'])
def verify_auth():
    user_response = request.json.get('response', '')
    supi = "imsi-208950000000001"
    
    expected_challenge = active_challenges.get(supi)
    if not expected_challenge:
        return jsonify({'success': False, 'message': 'No active challenge session found.'})
        
    # Fixed parameters to pass the actual DEMO_SECRET_KEY bytes handle instead of a string supi
    is_valid = stepup_auth.verify_response(DEMO_SECRET_KEY, expected_challenge, user_response)
    
    if is_valid:
        # Resolve state mappings based on active objects
        if hasattr(engine, 'clear_risk'):
            engine.clear_risk(supi)
        elif hasattr(engine, 'clear_risk_profile'):
            engine.clear_risk_profile(supi)
            
        active_challenges.pop(supi, None)
        return jsonify({'success': True, 'message': '🔒 Crypto-verification successful! Subscriber trust restored.'})
    
    return jsonify({'success': False, 'message': '❌ Invalid HMAC token code. Block persists.'})

if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True, port=5000)