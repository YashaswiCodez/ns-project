from flask import Flask, request, jsonify, render_template # type: ignore
import ssl
import socket
from datetime import datetime

app = Flask(__name__)

def get_certificate_info(hostname, port=443):
    """Fetch SSL/TLS certificate details from a website."""
    context = ssl.create_default_context()

    try:
        # Establish a connection and fetch the certificate
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Extract certificate details
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        valid_to = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        current_date = datetime.utcnow()

        # Analyze certificate validity
        is_valid = valid_from <= current_date <= valid_to
        days_left = (valid_to - current_date).days

        return {
            "Subject": subject,
            "Issuer": issuer,
            "Valid From": valid_from.strftime("%Y-%m-%d %H:%M:%S"),
            "Valid To": valid_to.strftime("%Y-%m-%d %H:%M:%S"),
            "Is Valid": is_valid,
            "Days Left": days_left,
        }
    except Exception as e:
        return {"Error": str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    domain = request.form.get('domain')
    if not domain:
        return jsonify({"Error": "No domain provided"}), 400
    
    result = get_certificate_info(domain.strip())
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)
