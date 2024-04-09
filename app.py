import os
import subprocess
from flask import Flask, request, send_file
 
nebula_pub_key_format_checks_enabled = True
# To improve security avoid giving too much info back to the user, keep False. To debug set to True.
detailed_error_response = True

app = Flask(__name__)

CERTIFICATE_DIRECTORY = ''  # No need to specify a directory if the certificates are already in the current directory

@app.route('/generate_certificate', methods=['POST'])
def generate_certificate():
    # Check if request contains a file
    file = request.files.get('file')
    if not file:
        return "No file provided in the request.", 400

    # Save the uploaded .pub file
    pub_key_path = os.path.join(CERTIFICATE_DIRECTORY, file.filename)
    file.save(pub_key_path)
    
    if nebula_pub_key_format_checks_enabled:
        # Validate the format of the .pub key
        validation_result = validate_pub_key_format(pub_key_path)
        if not validation_result['success']:
            os.remove(pub_key_path)  # Removing current .pub file
            if detailed_error_response:
                return validation_result['message'], 400
            else: 
                return "Error generating certificate!", 400

    # Get parameters from request
    name = request.form.get('name')
    ip_address = request.form.get('ip_address')
    groups = request.form.get('groups')

    # Execute nebula-cert command to generate certificate
    command = f'nebula-cert sign -in-pub {pub_key_path} -name "{name}" -ip "{ip_address}" --groups "{groups}" -duration 8h -ca-key /etc/nebula/ca.key -ca-crt /etc/nebula/ca.crt'

    try:
        subprocess.check_output(command, shell=True)
        certificate_path = name + '.crt'
    except subprocess.CalledProcessError as e:
        os.remove(pub_key_path)  # Removing current .pub file
        return f"Error generating certificate!", 500

    # Send the generated certificate file to the client
    response = send_file(certificate_path, as_attachment=True)

    # Removing .crt and .pub files from current folder
    os.remove(certificate_path)
    os.remove(pub_key_path)

    return response

def validate_pub_key_format(pub_key_path):
    # Check if the file exists
    if not os.path.exists(pub_key_path):
        return {'success': False, 'message': f"Error: File {pub_key_path} not found."}

    # Define the expected patterns
    begin_pattern = "-----BEGIN NEBULA X25519 PUBLIC KEY-----"
    end_pattern = "-----END NEBULA X25519 PUBLIC KEY-----"

    # Read the content of the file
    with open(pub_key_path, 'r') as f:
        pub_key = f.read().strip()

    # Check if the key starts and ends with the correct patterns
    if pub_key.startswith(begin_pattern) and pub_key.endswith(end_pattern):
        # Extract the middle pattern from the key
        middle_pattern = pub_key.split(begin_pattern)[-1].split(end_pattern)[0].strip()
        # Check if the middle pattern ends with "=" and has length 44 and doesn't contain whitespace
        if len(middle_pattern) == 44 and middle_pattern.endswith('=') and not any(char.isspace() for char in middle_pattern):
            return {'success': True, 'message': "The key is correctly formatted."}
        else:
            return {'success': False, 'message': "Error: Middle pattern is not correctly formatted."}
    else:
        return {'success': False, 'message': "Error: Key is not correctly formatted."}

if __name__ == '__main__':
    app.run(debug=True)
