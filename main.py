from flask import Flask, request, jsonify
import subprocess
import json

app = Flask(__name__)

# Define severities that are not allowed
disallowed_severities = ["Medium", "High", "Critical"]


@app.route('/validate', methods=['POST'])
def validate_admission_request():
    admission_review = request.get_json()
    resource = admission_review['request']['object']

    # Check if the resource has already been scanned by Grype
    if not is_scanned_by_grype(resource):
        # If not scanned, deny the request
        admission_response = {
            'allowed': False,
            'status': {
                'reason': 'Resource not scanned by Grype'
            }
        }
    else:
        # If scanned, check the severity of vulnerabilities
        vulnerabilities = get_vulnerabilities_from_grype(resource)
        if any(vuln['severity'] in disallowed_severities for vuln in vulnerabilities):
            # If vulnerabilities with disallowed severities are found, deny the request
            admission_response = {
                'allowed': False,
                'status': {
                    'reason': 'Vulnerabilities with disallowed severities found'
                }
            }
        else:
            # If no disallowed vulnerabilities found, allow the request
            admission_response = {
                'allowed': True
            }

    return jsonify({
        'response': admission_response
    })


def is_scanned_by_grype(resource):
    # Implement logic to check if the resource has been scanned by Grype
    # For example, you might check for specific annotations or labels
    return 'grype-scanned' in resource.get('metadata', {}).get('annotations', {})


def get_vulnerabilities_from_grype(resource):
    # Implement logic to extract vulnerabilities from Grype scan results
    # You'll need to parse Grype's JSON output or use its API
    # Example:
    grype_output = subprocess.check_output(['grype', '--json', 'your-container-image'])
    return json.loads(grype_output)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context=('python/certificate.cert', 'python/private.key'))
