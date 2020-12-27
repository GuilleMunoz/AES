# AES
Cython implementation of the Advanced Encryption Standard (Rijndael).

## Description

Aes algorithm is a symetric key encryption block cipher capable of handling 128 bits (16 bytes) blocks using keys of size 128, 192 or 256 bits.
AES consists of multiple encryption rounds. On each, the cipher performs a series of mathematic transformation:
- AddRoundKey
- SubBytes
- ShiftRows
- MixColumns

Similary, for the inverse cipher each transformation has its inverse (except for AddRoundKey):

- InvSubBytes
- InvShiftRows
- InvMixColumns

For futher information refer to the Federal Information Processing Standard Publication.

---

## Usage

### To encrypt or decrypt a single block
```python
from AES import AES

text = [00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
key_128 = [00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]


aes = AES(128, key_128)
cipher_text = aes.cipher(text) # Encrypt
inv_cipher_text = aes.inv_cipher(cipher_text) # Decrypt
```

### To encrypt or decrypt a file

```python
from AES import AES

aes = AES(256, key_256)
aes.process_file('el_quijote.txt', 'cipher.txt') # Encrypt

aes.process_file('cipher.txt', 'invcipher.txt', cipher=False) # Decrypt
```
When encrypting a file, if number of bytes in the file is not a multiple of 16, it adds 0x80 and (16 - nbytes mod 16 - 1) ASCII character 0 (<NULL>) at the end of the file.

## Performance

It manages to encrypt the first part of *Don Quixote* (more than one million bytes) in just 0.094 seconds and decrypts it in 0.65. This difference is due to the fact that InvMixColumns is much slower than MixColumns.
