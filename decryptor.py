#!/usr/bin/env python
# jnm 20161104

import base64
import hashlib
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from lxml import etree

IV_BYTE_LENGTH = 16

if len(sys.argv) != 3:
    print('Usage: {} [MyPrivateKey.pem] [submission.xml]'.format(sys.argv[0]))
    sys.exit(1)
PRIVATE_KEY_PEM_FILENAME = sys.argv[1]
STUB_SUBMISSION_FILENAME = sys.argv[2]

# XML tags of interest in the stub `submission.xml`
META_INSTANCE_ID_TAG = \
    "{http://openrosa.org/xforms}meta/{http://openrosa.org/xforms}instanceID"
B64_ENC_SYM_KEY_TAG = 'base64EncryptedKey'
ENC_XML_FILENAME_TAG = 'encryptedXmlFile'
B64_ENC_SIG_TAG = 'base64EncryptedElementSignature'

# The layout of the stub XML seems to have changed over the years; try a few
# possibilities when searching for elements
XML_NAMESPACES_TO_TRY = [
    'http://www.opendatakit.org/xforms/encrypted',  # 2016
    'http://opendatakit.org/submissions',           # 2022
]

# Read useful data from the stub `submission.xml`
stub_tree = etree.parse(
    STUB_SUBMISSION_FILENAME, etree.XMLParser(recover=True))
stub_root = stub_tree.getroot()
assert(stub_root.attrib['encrypted'] == 'yes')

# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/FileSystemUtils.java#L790
instance_id = stub_root.find(META_INSTANCE_ID_TAG).text

form_id = stub_root.attrib['id']
for ns in XML_NAMESPACES_TO_TRY:
    b64_enc_sym_elem = stub_root.find(f'{{{ns}}}{B64_ENC_SYM_KEY_TAG}')
    if b64_enc_sym_elem is not None:
        break
else:
    raise Exception("Uh oh! Couldn't figure out this XML stub submission")
b64_enc_sym_key = b64_enc_sym_elem.text

encrypted_xml_filename = stub_root.find(f'{{{ns}}}{ENC_XML_FILENAME_TAG}').text
b64_enc_sig = stub_root.find(f'{{{ns}}}{B64_ENC_SIG_TAG}').text

# Read the user's private key
with open(PRIVATE_KEY_PEM_FILENAME, 'rb') as f:
    pem_data = f.read()
private_key = load_pem_private_key(
    data=pem_data, password=None, backend=default_backend())

# Read the encrypted submission
encrypted_xml_path = os.path.join(
    os.path.dirname(STUB_SUBMISSION_FILENAME), encrypted_xml_filename
)
with open(encrypted_xml_path, 'rb') as f:
    enc_sub = f.read()

# Decrypt the symmetric key from the stub `submission.xml` using the user's
# private key. The asymmetric algorithm (in Java notation) is
# "RSA/NONE/OAEPWithSHA256AndMGF1Padding" per
# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/FileSystemUtils.java#L72
enc_sym_key = base64.decodebytes(b64_enc_sym_key.encode())
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
md5hasher.update(instance_id.encode())
md5hasher.update(sym_key)
iv_seed_digest = md5hasher.digest()
iv_seed_list = []
for i in range(IV_BYTE_LENGTH):
    fml = iv_seed_digest[(i % len(iv_seed_digest))]
    iv_seed_list.append(bytes((fml,)))
# What are they up to?
# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/CipherFactory.java#L74
iv_counter = 0 # Haven't yet investigated when this would increase
iv_seed_list[iv_counter % len(iv_seed_list)] = \
    bytes((iv_seed_list[iv_counter % len(iv_seed_list)][0] + 1,))

# Decrypt the encrypted submission using the symmetric key. The symmetric
# algorithm (in Java notation) is "AES/CFB/PKCS5Padding" per
# https://github.com/opendatakit/briefcase/blob/68170b4af0cf1d5a330fe1b8ffff948145df7757/src/org/opendatakit/briefcase/util/CipherFactory.java#L40
sym_cipher = Cipher(
    algorithms.AES(sym_key),
    modes.CFB(b''.join(iv_seed_list)),
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
enc_sig = base64.decodebytes(b64_enc_sig.encode())
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
md5_hex_plain_sub = md5hasher.hexdigest().encode()
signature_content = b'\n'.join((
    form_id.encode(),
    # would add "version" here if it were present
    b64_enc_sym_key.encode(),
    instance_id.encode(),
    b'submission.xml::' + md5_hex_plain_sub + b'\n',
))
md5hasher = hashlib.md5()
md5hasher.update(signature_content)
computed_sig = md5hasher.digest()
if computed_sig == plain_sig:
    print(plain_sub.decode())
else:
    print('!!! SIGNATURE VERIFICATION FAILED !!!')
    input('Press enter to see the decrypted submission anyway...')
    print(plain_sub)
