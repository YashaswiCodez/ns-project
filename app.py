import socket
import ssl
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

def get_ssl_details(domain):
    try:
        # Establish a socket connection to fetch SSL certificate
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        
        # Extract certificate details
        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])
        valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        valid_to = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_left = (valid_to - datetime.utcnow()).days
        
        return {
            "Subject": subject,
            "Issuer": issuer,
            "Valid From": valid_from.strftime("%Y-%m-%d"),
            "Valid To": valid_to.strftime("%Y-%m-%d"),
            "Is Valid": valid_to > datetime.utcnow(),
            "Days Left": days_left
        }
    except Exception as e:
        return {"Error": str(e)}

@app.route('/analyze', methods=['POST'])
def analyze():
    domain = request.form.get('domain')
    if not domain:
        return jsonify({"Error": "No domain provided"}), 400
    
    # Fetch SSL details for the provided domain
    ssl_details = get_ssl_details(domain)
    return jsonify(ssl_details)

if __name__ == '__main__':
    app.run(debug=True)
