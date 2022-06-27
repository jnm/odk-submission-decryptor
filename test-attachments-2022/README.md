To decrypt an attachment, you can try code like this in IPython after `%run`ning `decryptor.py`:
```python
att_decryptor = sym_cipher.decryptor()
att_encrypted = open('signature-1_8_45.png.enc', 'rb').read()
att_plain_padded = att_decryptor.update(att_encrypted) + att_decryptor.finalize()
att_unpadder = padding.PKCS7(sym_cipher.algorithm.block_size).unpadder()
att_plain = att_unpadder.update(att_plain_padded) + att_unpadder.finalize()
f = open('test.png', 'wb')
f.write(att_plain)
f.close()
```

Example:
```
test-attachments-2022$ ipython
Python 3.10.5 (main, Jun 11 2022, 16:53:24) [GCC 9.4.0]
Type 'copyright', 'credits' or 'license' for more information
IPython 8.4.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: %run ../decryptor.py MyPrivateKey.pem submission.xml
!!! SIGNATURE VERIFICATION FAILED !!!
Press enter to see the decrypted submission anyway...
b'\xab\xbf-m\xd1\xf6\xbd>R\xd1\xeb\xe8\xb0\xdf\xf1oT38fWEi xmlns:jr="http://openrosa.org/javarosa" xmlns:orx="http://openrosa.org/xforms" id="aZ4JbULPY6UwPPyT38fWEi" version="2 (2022-02-08 06:08:18)">\n          <formhub>\n            <uuid>fa9a7633c1cd455b83b1204e09982016</uuid>\n          </formhub>\n          <start>2022-02-08T01:08:34.664-05:00</start>\n          <end>2022-02-08T01:08:50.836-05:00</end>\n          <sign_now type="file">signature-1_8_45.png</sign_now>\n          <sign_again type="file">signature-1_8_48.png</sign_again>\n          <groupy>\n            <second_page/>\n          </groupy>\n          <__version__>vBJ4aJgMpFHS4HJAu6CYGP</__version__>\n          <_version_>vPu4X5zGi78af28Y32URCz</_version_>\n          <meta>\n            <instanceID>uuid:8fd94989-29b8-4577-be41-165280cbd976</instanceID>\n          </meta>\n        </aZ4JbULPY6UwPPyT38fWEi>'

In [2]: att_decryptor = sym_cipher.decryptor()
   ...: att_encrypted = open('signature-1_8_45.png.enc', 'rb').read()
   ...: att_plain_padded = att_decryptor.update(att_encrypted) + att_decryptor.finalize()
   ...: att_unpadder = padding.PKCS7(sym_cipher.algorithm.block_size).unpadder()
   ...: att_plain = att_unpadder.update(att_plain_padded) + att_unpadder.finalize()
   ...: f = open('test.png', 'wb')
   ...: f.write(att_plain)
   ...: f.close()
   ...: 
```

Clearly, there's an issue with signature verificaiton (the attachments probably need to be
included in the signature somehow?), **and** trying to decrypt the *other* PNG
(`signature-1_8_48.png.enc`) gives me a corrupted file. I would try a fresh project before worrying
about the corrupted file, though, because it's possible it was corrupted before it was encrypted.
