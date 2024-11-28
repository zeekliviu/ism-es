from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
import cryptography.x509 as x509
import datetime

# Generate an RSA private key
def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key

# Generate a Certificate Signing Request (CSR)
def generate_csr(private_key, country, state, locality, org, org_unit, common_name, email):
    # Subject details
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])
    
    # Create CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        private_key, hashes.SHA256()
    )
    return csr

# Save private key to file
def save_private_key(private_key, filename):
    with open(filename, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

# Save CSR to file
def save_csr(csr, filename):
    with open(filename, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

# Main function
if __name__ == "__main__":
    # CSR details
    country = "US"
    state = "California"
    locality = "San Francisco"
    organization = "Example Corp"
    organizational_unit = "IT Department"
    common_name = "example.com"
    email_address = "admin@example.com"

    # Generate private key
    private_key = generate_private_key()
    save_private_key(private_key, "private_key.pem")

    # Generate CSR
    csr = generate_csr(
        private_key, country, state, locality, organization, organizational_unit, common_name, email_address
    )
    save_csr(csr, "certificate_request.csr")

    print("Private key and CSR have been generated.")
