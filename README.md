- certificate template engine for:
  - `server`
  - `client`
  - `code_signing`
- Subject Alternative Name (SAN) support
- end-entity certificate issuance from the Intermediate CA
- certificate chain validation using OpenSSL
- policy document update with Intermediate CA information

### Sprint 3
Sprint 3 adds certificate lifecycle management and a basic repository by implementing:

- SQLite certificate database
- unique serial number generation and tracking
- automatic database insertion on issuance
- certificate listing and retrieval from the database
- HTTP repository server for certificate access
- CA certificate endpoints
- CRL placeholder endpoint

## Technology Stack

- Python 3.11+
- cryptography
- sqlite3
- pytest
- OpenSSL

## Project Structure

```text
project_root/
├── main.py
├── setup.py
├── requirements.txt
├── pytest.ini
├── run_tests.bat
├── README.md
├── micropki/
│   ├── __init__.py
│   ├── cli.py
│   ├── ca.py
│   ├── certificates.py
│   ├── crypto_utils.py
│   ├── logger.py
│   ├── csr.py
│   ├── templates.py
│   ├── chain.py
│   ├── database.py
│   ├── repository.py
│   └── serial.py
└── tests/
    ├── test_crypto_utils.py
    ├── test_database.py
    ├── test_dn_parser.py
    ├── test_encrypted_key_loading.py
    ├── test_intermediate_and_leaf.py
    ├── test_key_and_certificate_match.py
    ├── test_serial.py
    └── test_templates.py
Installation

Create and activate a virtual environment if desired.

Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1

Install dependencies:

pip install -r requirements.txt

Install the package in editable mode to make the micropki command available:

pip install -e .
Dependencies

The project uses the following external libraries and tools:

Python 3.11+
cryptography>=3.4
pytest>=7.0
sqlite3 (standard library)
OpenSSL
Usage
1. Create a passphrase file

Create a file named ca.pass:

mypassword123
2. Initialize the certificate database
micropki db init --db-path .\pki\micropki.db
3. Initialize the Root CA
micropki ca init --subject "CN=Demo Root CA,O=MicroPKI,C=US" --key-type rsa --key-size 4096 --passphrase-file .\ca.pass --out-dir .\pki --db-path .\pki\micropki.db
4. Issue the Intermediate CA
micropki ca issue-intermediate --root-cert .\pki\certs\ca.cert.pem --root-key .\pki\private\ca.key.pem --root-pass-file .\ca.pass --subject "CN=MicroPKI Intermediate CA,O=MicroPKI,C=US" --key-type rsa --key-size 4096 --passphrase-file .\ca.pass --out-dir .\pki --validity-days 1825 --pathlen 0 --db-path .\pki\micropki.db
5. Issue a server certificate
micropki ca issue-cert --ca-cert .\pki\certs\intermediate.cert.pem --ca-key .\pki\private\intermediate.key.pem --ca-pass-file .\ca.pass --template server --subject "CN=example.com,O=MicroPKI,C=US" --san dns:example.com --san dns:www.example.com --san ip:192.168.1.10 --out-dir .\pki\certs --validity-days 365 --db-path .\pki\micropki.db
6. Issue a client certificate
micropki ca issue-cert --ca-cert .\pki\certs\intermediate.cert.pem --ca-key .\pki\private\intermediate.key.pem --ca-pass-file .\ca.pass --template client --subject "CN=Alice Smith,EMAIL=alice@example.com,O=MicroPKI,C=US" --san email:alice@example.com --out-dir .\pki\certs --validity-days 365 --db-path .\pki\micropki.db
7. Issue a code signing certificate
micropki ca issue-cert --ca-cert .\pki\certs\intermediate.cert.pem --ca-key .\pki\private\intermediate.key.pem --ca-pass-file .\ca.pass --template code_signing --subject "CN=MicroPKI Code Signer,O=MicroPKI,C=US" --out-dir .\pki\certs --validity-days 365 --db-path .\pki\micropki.db
Database Commands
Initialize database
micropki db init --db-path .\pki\micropki.db
List certificates

Default table output:

micropki ca list-certs --db-path .\pki\micropki.db

Filter by status:

micropki ca list-certs --db-path .\pki\micropki.db --status valid

JSON output:

micropki ca list-certs --db-path .\pki\micropki.db --format json

CSV output:

micropki ca list-certs --db-path .\pki\micropki.db --format csv
Show a certificate by serial
micropki ca show-cert 69D739D36A9B1324 --db-path .\pki\micropki.db
Repository Server

Start the HTTP repository server:

micropki repo serve --host 127.0.0.1 --port 8080 --db-path .\pki\micropki.db --cert-dir .\pki\certs

The server runs until interrupted.

Repository API
GET /certificate/<serial>

Returns the PEM certificate from the database.

Example:

Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/certificate/69D739D36A9B1324

Save to file:

Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/certificate/69D739D36A9B1324 -OutFile .\fetched-cert.pem
GET /ca/root

Returns the Root CA certificate.

Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/ca/root
GET /ca/intermediate

Returns the Intermediate CA certificate.

Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/ca/intermediate
GET /crl

Placeholder endpoint for Sprint 4.

Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/crl

Expected behavior:

status 501 Not Implemented
message: CRL generation not yet implemented
Output Layout

After Root CA and Intermediate CA generation, the directory layout is:

pki/
├── private/
│   ├── ca.key.pem
│   └── intermediate.key.pem
├── certs/
│   ├── ca.cert.pem
│   ├── intermediate.cert.pem
│   └── *.cert.pem
├── csrs/
│   └── intermediate.csr.pem
├── micropki.db
└── policy.txt

For issued end-entity certificates, files are created in the certificate output directory:

pki/certs/
├── example.com.cert.pem
├── example.com.key.pem
├── Alice_Smith.cert.pem
├── Alice_Smith.key.pem
├── MicroPKI_Code_Signer.cert.pem
└── MicroPKI_Code_Signer.key.pem
Certificate Templates
Server
Basic Constraints: CA=FALSE (critical)
Key Usage:
RSA: digitalSignature, keyEncipherment
ECC: digitalSignature
Extended Key Usage: serverAuth
SAN: at least one DNS or IP entry is required
Client
Basic Constraints: CA=FALSE (critical)
Key Usage: digitalSignature
Extended Key Usage: clientAuth
SAN: DNS and email SANs are supported
Code Signing
Basic Constraints: CA=FALSE (critical)
Key Usage: digitalSignature
Extended Key Usage: codeSigning
SAN: optional, limited to DNS or URI
SAN Format

Supported SAN argument format:

type:value

Supported SAN types:

dns
ip
email
uri

Examples:

dns:example.com
dns:www.example.com
ip:192.168.1.10
email:alice@example.com
uri:https://example.com/app
Logging
If --log-file is provided, logs are appended to that file.
If --log-file is omitted, logs are written to stderr.
Log entries include timestamp, level, and message.
Passphrases are never written to logs.
HTTP requests are logged with [HTTP] prefix.

The following operations are logged:

database initialization
Root CA key generation
Root CA certificate generation
Intermediate CA CSR generation
Intermediate CA certificate signing
certificate insertion into the database
certificate retrieval via CLI
end-entity certificate issuance
repository HTTP requests
validation failures and warnings
Verification with OpenSSL
Inspect Root CA certificate
openssl x509 -in .\pki\certs\ca.cert.pem -text -noout
Inspect Intermediate CA certificate
openssl x509 -in .\pki\certs\intermediate.cert.pem -text -noout
Inspect server certificate
openssl x509 -in .\pki\certs\example.com.cert.pem -text -noout
Verify Root CA self-signed certificate
openssl verify -CAfile .\pki\certs\ca.cert.pem .\pki\certs\ca.cert.pem

Expected result:

.\pki\certs\ca.cert.pem: OK
Verify Intermediate CA against Root CA
openssl verify -CAfile .\pki\certs\ca.cert.pem .\pki\certs\intermediate.cert.pem

Expected result:

.\pki\certs\intermediate.cert.pem: OK
Verify leaf certificate against full chain
openssl verify -CAfile .\pki\certs\ca.cert.pem -untrusted .\pki\certs\intermediate.cert.pem .\pki\certs\example.com.cert.pem

Expected result:

.\pki\certs\example.com.cert.pem: OK
Running Tests

Run all tests using the provided script:

.\run_tests.bat

Or directly:

pytest