# MicroPKI

MicroPKI is a minimal Public Key Infrastructure (PKI) project for educational purposes.  
The project demonstrates the core PKI workflow by implementing a self-signed Root CA, an Intermediate CA, and issuance of end-entity certificates using predefined templates.

## Sprint 1 and Sprint 2 Scope

### Sprint 1
Sprint 1 established the PKI foundation by implementing:

- Root CA initialization;
- encrypted private key storage;
- self-signed X.509 v3 Root CA certificate generation;
- policy document generation;
- audit logging;
- automated unit tests.

### Sprint 2
Sprint 2 extends the PKI by implementing:

- Intermediate CA generation and signing by the Root CA;
- CSR generation for the Intermediate CA;
- certificate template engine for:
  - `server`
  - `client`
  - `code_signing`
- Subject Alternative Name (SAN) support;
- end-entity certificate issuance from the Intermediate CA;
- certificate chain validation using OpenSSL;
- policy document update with Intermediate CA information.

## Technology Stack

- Python 3.11+
- cryptography
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
│   └── chain.py
└── tests/
    ├── test_crypto_utils.py
    ├── test_dn_parser.py
    ├── test_encrypted_key_loading.py
    ├── test_key_and_certificate_match.py
    ├── test_templates.py
    └── test_intermediate_and_leaf.py
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
OpenSSL
Usage
1. Create a passphrase file

Create a file named ca.pass:

mypassword123
2. Initialize the Root CA
micropki ca init --subject "CN=Demo Root CA,O=MicroPKI,C=US" --key-type rsa --key-size 4096 --passphrase-file .\ca.pass --out-dir .\pki
3. Issue the Intermediate CA
micropki ca issue-intermediate --root-cert .\pki\certs\ca.cert.pem --root-key .\pki\private\ca.key.pem --root-pass-file .\ca.pass --subject "CN=MicroPKI Intermediate CA,O=MicroPKI,C=US" --key-type rsa --key-size 4096 --passphrase-file .\ca.pass --out-dir .\pki --validity-days 1825 --pathlen 0
4. Issue a server certificate
micropki ca issue-cert --ca-cert .\pki\certs\intermediate.cert.pem --ca-key .\pki\private\intermediate.key.pem --ca-pass-file .\ca.pass --template server --subject "CN=example.com,O=MicroPKI,C=US" --san dns:example.com --san dns:www.example.com --san ip:192.168.1.10 --out-dir .\pki\certs --validity-days 365
5. Issue a client certificate
micropki ca issue-cert --ca-cert .\pki\certs\intermediate.cert.pem --ca-key .\pki\private\intermediate.key.pem --ca-pass-file .\ca.pass --template client --subject "CN=Alice Smith,EMAIL=alice@example.com,O=MicroPKI,C=US" --san email:alice@example.com --out-dir .\pki\certs --validity-days 365
6. Issue a code signing certificate
micropki ca issue-cert --ca-cert .\pki\certs\intermediate.cert.pem --ca-key .\pki\private\intermediate.key.pem --ca-pass-file .\ca.pass --template code_signing --subject "CN=MicroPKI Code Signer,O=MicroPKI,C=US" --out-dir .\pki\certs --validity-days 365
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
└── policy.txt

For issued end-entity certificates, files are created in the output certificate directory:

pki/certs/
├── example.com.cert.pem
└── example.com.key.pem
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

The following operations are logged:

Root CA key generation
Root CA certificate generation
Intermediate CA CSR generation
Intermediate CA certificate signing
End-entity certificate issuance
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
Implemented Features
Sprint 1
CLI parser based on argparse
ca init subcommand
input validation for Root CA generation
RSA 4096-bit and ECC P-384 Root CA key generation
encrypted private key serialization using BestAvailableEncryption
self-signed X.509 v3 Root CA certificate generation
Basic Constraints, Key Usage, SKI, AKI
policy file generation
audit logging
unit tests
Sprint 2
ca issue-intermediate subcommand
ca issue-cert subcommand
Intermediate CA PKCS#10 CSR generation
Intermediate CA certificate signing by Root CA
certificate template engine (server, client, code_signing)
SAN parsing and validation
end-entity key generation and certificate issuance
certificate chain verification with OpenSSL
policy file update with Intermediate CA section
additional unit tests for SAN parsing, template validation, and intermediate/leaf issuance
Security Notes
Root CA and Intermediate CA private keys are stored in encrypted PEM format.
The passphrase is read from a file as bytes and trailing newlines are stripped.
End-entity private keys are stored unencrypted as required by Sprint 2.
A warning is emitted when an end-entity private key is written unencrypted.
Existing CA files are not overwritten.
On Unix-like systems, the code attempts to apply restrictive permissions.
On Windows, POSIX permission modes may not be fully enforceable.
Current Limitations
CSR signing via external --csr input is not implemented yet.
Dedicated internal chain-validation command is not implemented; OpenSSL is used for documented validation.
TLS round-trip demo with openssl s_server / openssl s_client is not included yet.
Negative integration tests are only partially covered through unit tests and CLI validation.