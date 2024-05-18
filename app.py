import os
import subprocess
import ipaddress
import re
import shlex
from flask import Flask, request, send_file

nebula_pub_key_format_checks_enabled = True
# To improve security avoid giving too much info back to the user, keep False. To debug set to True.
detailed_error_response = True

#allowed characters in the group field (no spaces!)
allowed_characters = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_')

app = Flask(__name__)

CERTIFICATE_DIRECTORY = ''  # No need to specify a directory if the certificates are already in the current directory

@app.route('/generate_certificate', methods=['GET', 'POST'])
def generate_certificate():

    print("Request received")

    if request.method == 'GET':
        return 'Send a POST request with data', 200

    # Get other parameters from request
    name = request.form.get('name')
    ip_address = request.form.get('ip_address')
    groups = request.form.get('groups')
    pub_key = request.form.get('key')

    if not pub_key:
        return "No key provided in the request.", 400

    # Sanitize inputs
    sanitized_name = sanitize_string(shlex.quote(name))
    sanitized_ip_address = shlex.quote(ip_address)
    sanitized_groups = shlex.quote(''.join(char for char in groups if char in allowed_characters))
    sanitized_pub_key = pub_key

    # Save the uploaded .pub file
    pub_key_path = os.path.join(CERTIFICATE_DIRECTORY, "temp.pub")
    key_file = open(pub_key_path, "w")
    key_file.write(sanitized_pub_key)
    key_file.close()
    
    # Input validation
    if not os.path.isfile(pub_key_path):
        if detailed_error_response:
            return "Bad file name!", 400
        else: 
            return "Error generating certificate!", 400
        
    if not validate_ip_with_subnet(ip_address):
        if detailed_error_response:
            return "Bad IP, make sure to have IP/subnet!", 400
        else: 
            return "Error generating certificate!", 400
    
    if nebula_pub_key_format_checks_enabled:
        # Validate the format of the .pub key
        validation_result = validate_pub_key_format(pub_key_path)
        if not validation_result['success']:
            os.remove(pub_key_path)  # Removing current .pub file
            if detailed_error_response:
                return validation_result['message'], 400
            else: 
                return "Error generating certificate!", 400

    # Execute nebula-cert command to generate certificate
    command = f'nebula-cert sign -in-pub {pub_key_path} -name "{sanitized_name}" -ip "{sanitized_ip_address}" --groups "{sanitized_groups}" -duration 8h -ca-key /etc/nebula/ca.key -ca-crt /etc/nebula/ca.crt'

    try:
        subprocess.check_output(command, shell=True)
        certificate_path = sanitized_name + '.crt'
    except subprocess.CalledProcessError as e:
        os.remove(pub_key_path)  # Removing created .pub file
        return f"Error generating certificate!", 500

    # Send the generated certificate file to the client
    response = send_file(certificate_path, as_attachment=True)

    # Removing .crt and .pub files from current folder
    os.remove(certificate_path)
    os.remove(pub_key_path)

    return response

def sanitize_string(input_string):
    # Strip underscores
    clean_string = input_string.replace('_', '')
    # Replace spaces with underscores
    clean_string = clean_string.replace(' ', '_')
    # Remove non-alphanumeric characters except underscores
    clean_string = re.sub(r'[^a-zA-Z0-9_]', '', clean_string)
    # Lowercase the string
    clean_string = clean_string.lower()
    return clean_string

def validate_ip_with_subnet(ip_with_subnet):
    try:
        ipaddress.ip_network(ip_with_subnet, strict=False)
        return True
    except:
        return False

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
    app.run(host='0.0.0.0', port=5000, debug=True)
