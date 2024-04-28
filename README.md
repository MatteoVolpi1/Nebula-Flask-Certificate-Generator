# Flask API

## Prerequisites
- Python 3 installed on your system
- Flask library installed (`pip install Flask`)
- [Nebula scalable overlay network](https://github.com/slackhq/nebula#distribution-packages)

## Running the API
1. Clone this repository to your local machine.
2. Navigate to the project directory.
3. Run the Flask application with the following command:
   ```
   python3 app.py
   ```
   This will start the Flask API server.

## Generating Certificates
To generate certificates using the API, you can make a POST request with the necessary parameters. Here's how you can do it using `curl`:

```bash
curl -X POST \
  --data-binary "key=<key_contents>" \
  -d "name=<Hostname>" \
  -d "ip_address=<Nebula_ip_address>" \
  -d "groups=<Nebula_security_groups>" \
  http://localhost:5000/generate_certificate

```

### Parameters:
- `file`: The public key file to be included in the certificate. Make sure to replace `Hostname.pub` with the path to your Nebula public key file.
- `name`: The name to be included in the certificate.
- `ip_address`: The IP address to be included in the certificate. Replace `<ip_address>` with the actual Nebula IP address.
- `groups`: Comma-separated list of groups for the certificate.

### Output:
- Text content of the signed Nebula certificate

## Additional Notes
- Ensure that the Flask API server is running (`python3 app.py`) before making requests.
