from M2Crypto import SMIME, X509, BIO

# Paths to necessary files
PRIVATE_KEY_FILE = "private.key"  # Path to your private key
CERTIFICATE_FILE = "certificate.pem"  # Path to your certificate
DATA_FILE = "dummy.txt"  # Path to the file to be signed
OUTPUT_SIGNATURE = "signed_dummy.p7s"  # Output PKCS#7 signature file

def create_pkcs7_signature(data_file, private_key_file, certificate_file, output_signature):
    # Create an SMIME object
    smime = SMIME.SMIME()

    # Load the signer's certificate
    smime.load_key(private_key_file, certificate_file)

    # Read the data to be signed
    with open(data_file, "rb") as f:
        data_bio = BIO.MemoryBuffer(f.read())

    # Create a PKCS#7 signature
    pkcs7 = smime.sign(data_bio, SMIME.PKCS7_DETACHED)

    # Write the signature to a file
    with open(output_signature, "wb") as f:
        out_bio = BIO.File(f)
        smime.write(out_bio, pkcs7, data_bio)
    
    print(f"PKCS#7 signature created and saved to {output_signature}")

if __name__ == "__main__":
    create_pkcs7_signature(DATA_FILE, PRIVATE_KEY_FILE, CERTIFICATE_FILE, OUTPUT_SIGNATURE)
