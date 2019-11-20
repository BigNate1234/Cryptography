'''
  ||
  || @file   generateKeyU1.py
  || @version  1.0
  || @author  bignate1234
  || @contact  nfurman@ieee.org
  ||
  || @description
  || | Generates a public and private key for User1, writes to files.
  || #
  ||
  || @license
  || | This library is free software; you can redistribute it and/or
  || | modify it under the terms of the GNU Lesser General Public
  || | License as published by the Free Software Foundation; version
  || | 2.1 of the License.
  || |
  || | This library is distributed in the hope that it will be useful,
  || | but WITHOUT ANY WARRANTY; without even the implied warranty of
  || | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  || | Lesser General Public License for more details.
  || |
  || | You should have received a copy of the GNU Lesser General Public
  || | License along with this library; if not, write to the Free Software
  || | Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
  || #
  ||
'''

import os
import sys
import base64
import getpass
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as paddingAsym
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature

debug = False

def writeKeys(kr_fname, ku_fname, passwd, size=2048, backend=default_backend()):
  private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=size,
    backend=backend
  )

  # Generate public from private
  public_key = private_key.public_key()

  if debug:
    print("Private:",private_key)
    print("Public :",public_key)
  
  pem_kr = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(passwd.encode())
  )

  # Generate pulbic un-encrypted key
  pem_ku = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
  )

  if debug:
    print("Private pem:",pem_kr)
    print("Public pem :",pem_ku)
  
  try:
    with open(kr_fname, 'w') as file:
      file.write(pem_kr.decode("utf-8"))
      file.close()
  except IOError:
    print("Could not read file:", kr_fname)
    raise IOError
    return False

  try:
    with open(ku_fname, 'w') as file:
      file.write(pem_ku.decode("utf-8"))
      file.close()
  except IOError:
    print("Could not read file:", ku_fname)
    raise IOError
    return False

  return private_key, public_key

kr_fname = "ksU1/krU1.pem"
ku_fname = "ksU1/kuU1.pem"
key_pass = "hello"
if not debug:
  #key_pass  = str.encode(getpass.getpass("Please input key password for User1:"))
  key_pass  = getpass.getpass("Please input key password for User1:")

print("Writing User1's keys")

try:
  writeKeys(kr_fname=kr_fname, ku_fname=ku_fname, passwd=key_pass)
except IOError:
  print("Writing keys failed")

'''
  || @changelog
  || | 1.0 2019-11-20 - big_nate1234 : Initial Public Release
  || #
'''
