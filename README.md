\# MicroPKI



MicroPKI is a minimal Public Key Infrastructure (PKI) project that implements a self-signed Root Certificate Authority (Root CA) for educational purposes.



\## Sprint 1 Scope



Sprint 1 establishes the PKI foundation by implementing:



\- a command-line interface for Root CA initialization;

\- secure encrypted private key storage;

\- generation of a self-signed X.509 v3 Root CA certificate;

\- policy document generation;

\- basic audit logging;

\- automated unit tests.



\## Technology Stack



\- Python 3.11+

\- cryptography

\- pytest

\- OpenSSL (for manual verification)



\## Project Structure



```text

project\_root/

├── main.py

├── requirements.txt

├── pytest.ini

├── README.md

├── micropki/

│   ├── \_\_init\_\_.py

│   ├── cli.py

│   ├── ca.py

│   ├── certificates.py

│   ├── crypto\_utils.py

│   └── logger.py

└── tests/

&#x20;   ├── test\_crypto\_utils.py

&#x20;   └── test\_dn\_parser.py

Installation

Create and activate a virtual environment (optional but recommended).

Windows PowerShell

python -m venv .venv

.venv\\Scripts\\Activate.ps1

Install dependencies:

pip install -r requirements.txt

Dependencies



Listed in requirements.txt:



cryptography>=3.4

pytest>=7.0

Usage



Create a passphrase file first, for example ca.pass:



mypassword123



Run Root CA initialization:



python main.py ca init --subject "CN=Demo Root CA,O=MicroPKI,C=US" --key-type rsa --key-size 4096 --passphrase-file .\\ca.pass --out-dir .\\pki

Output



After successful execution, the following structure is created:



pki/

├── private/

│   └── ca.key.pem

├── certs/

│   └── ca.cert.pem

└── policy.txt

Verification with OpenSSL



Inspect certificate contents:



openssl x509 -in .\\pki\\certs\\ca.cert.pem -text -noout



Verify the self-signed certificate:



openssl verify -CAfile .\\pki\\certs\\ca.cert.pem .\\pki\\certs\\ca.cert.pem



Expected result:



.\\pki\\certs\\ca.cert.pem: OK

Running Tests

pytest

Notes on Security

The private key is stored in encrypted PEM format using BestAvailableEncryption.

The passphrase is read from a file and is never printed to logs.

On Unix-like systems, the code attempts to apply restrictive permissions to private key material.

On Windows, POSIX permission modes may not be fully enforced by the operating system.

Current Limitations

Sprint 1 implements only Root CA initialization.

No Intermediate CA, CRL, OCSP, or certificate issuance workflows are included yet.

No separate micropki ca verify command has been added; OpenSSL is used for verification instead.

