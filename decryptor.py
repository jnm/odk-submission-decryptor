#!/usr/bin/python
# jnm 20161104

import base64
import hashlib
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from lxml import etree

IV_BYTE_LENGTH = 16

# Read from command line?
STUB_SUBMISSION_FILENAME = 'submission.xml'

if len(sys.argv) != 2:
    print 'Usage: {} [MyPrivateKey.pem]'.format(sys.argv[0])
    sys.exit(1)
PRIVATE_KEY_PEM_FILENAME = sys.argv[1]

# XML tags of interest in the stub `submission.xml`
B64_ENC_SYM_KEY_TAG = \
    '{http://www.opendatakit.org/xforms/encrypted}base64EncryptedKey'
ENC_XML_FILENAME_TAG = \
    '{http://www.opendatakit.org/xforms/encrypted}encryptedXmlFile'
B64_ENC_SIG_TAG = \
    '{http://www.opendatakit.org/xforms/encrypted}base64EncryptedElementSignature'

# Read useful data from the stub `submission.xml`
stub_tree = etree.parse(
    STUB_SUBMISSION_FILENAME, etree.XMLParser(recover=True))
stub_root = stub_tree.getroot()
assert(stub_root.attrib['encrypted'] == 'yes')
# Instance ID is really pulled from the "OpenRosa meta block", but that was
# identical to the root `instanceID` attribute in my test files
# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/FileSystemUtils.java#L790
instance_id = stub_root.attrib['instanceID']
form_id = stub_root.attrib['id']
b64_enc_sym_key = stub_root.find(B64_ENC_SYM_KEY_TAG).text
encrypted_xml_filename = stub_root.find(ENC_XML_FILENAME_TAG).text
b64_enc_sig = stub_root.find(B64_ENC_SIG_TAG).text

# Read the user's private key
with open(PRIVATE_KEY_PEM_FILENAME) as f:
    pem_data = f.read()
private_key = load_pem_private_key(
    data=pem_data, password=None, backend=default_backend())

# Read the encrypted submission
with open(encrypted_xml_filename) as f:
    enc_sub = f.read()

# Decrypt the symmetric key from the stub `submission.xml` using the user's
# private key. The asymmetric algorithm (in Java notation) is
# "RSA/NONE/OAEPWithSHA256AndMGF1Padding" per
# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/FileSystemUtils.java#L72
enc_sym_key = base64.decodestring(b64_enc_sym_key)
sym_key = private_key.decrypt(
    enc_sym_key,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Construct the IV from the MD5 of the instance ID and the symmetric key, per
# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/CipherFactory.java#L52
md5hasher = hashlib.md5()
md5hasher.update(instance_id)
md5hasher.update(sym_key)
iv_seed_digest = md5hasher.digest()
iv_seed_list = []
for i in range(IV_BYTE_LENGTH):
   iv_seed_list.append(iv_seed_digest[(i % len(iv_seed_digest))])
# What are they up to?
# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/CipherFactory.java#L74
iv_counter = 0 # Haven't yet investigated when this would increase
iv_seed_list[iv_counter % len(iv_seed_list)] = \
    chr(ord(iv_seed_list[iv_counter % len(iv_seed_list)]) + 1)

# Decrypt the encrypted submission using the symmetric key. The symmetric
# algorithm (in Java notation) is "AES/CFB/PKCS5Padding" per
# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/CipherFactory.java#L40
sym_cipher = Cipher(
    algorithms.AES(sym_key),
    modes.CFB(''.join(iv_seed_list)),
    backend=default_backend()
)
sym_decryptor = sym_cipher.decryptor()
padded_plain_sub = sym_decryptor.update(enc_sub) + sym_decryptor.finalize()

# Remove the padding
unpadder = padding.PKCS7(sym_cipher.algorithm.block_size).unpadder()
plain_sub = unpadder.update(padded_plain_sub) + unpadder.finalize()

# Decrypt the signature stored in the stub `submission.xml` using the user's
# private key, per
# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/FileSystemUtils.java#L528
enc_sig = base64.decodestring(b64_enc_sig)
plain_sig = private_key.decrypt(
    enc_sig,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Verify the signature, per
# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/FileSystemUtils.java#L668
md5hasher = hashlib.md5()
md5hasher.update(plain_sub)
md5_hex_plain_sub = md5hasher.hexdigest()
signature_content = '\n'.join((
    form_id,
    # would add "version" here if it were present
    b64_enc_sym_key,
    instance_id,
    'submission.xml::{}\n'.format(md5_hex_plain_sub)
))
md5hasher = hashlib.md5()
md5hasher.update(signature_content)
computed_sig = md5hasher.digest()
if computed_sig == plain_sig:
    print plain_sub
else:
    print '!!! SIGNATURE VERIFICATION FAILED !!!'
    raw_input('Press enter to see the decrypted submission anyway...')
    print plain_sub
