'''
  ||
  || @file   generateU2Cert.py
  || @version  1.0
  || @author  bignate1234
  || @contact  nfurman@ieee.org
  ||
  || @description
  || | Generates a certificate key for User2, writes to file.
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

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import datetime
import getpass

debug = False
one_day = datetime.timedelta(1, 0, 0)

# Get public and private keys generated before
def readKeys(kr_fname, ku_fname, passwd, backend=default_backend()):
  # Reading keys for serrialization
  try:
    with open(kr_fname, 'rb') as file:
      private_key_temp = file.read()
      file.close()
  except IOError:
    print("Could not read file:", kr_fname)
    raise IOError
    return False
  
  try:
    with open(ku_fname, 'rb') as file:
      public_key_temp = file.read()
      file.close()
  except IOError:
    print("Could not read file:", ku_fname)
    raise IOError
    return False
  
  if debug:
    print("PrivateTemp:",private_key_temp)
    print("PublicTemp :",public_key_temp)

  private_key = serialization.load_pem_private_key(
    data=private_key_temp,
    password=passwd.encode(),
    backend=backend
  )

  public_key = serialization.load_pem_public_key(
    data=public_key_temp,
    backend=backend
  )
  
  if debug:
    print("Private Key:",private_key)
    print("Public Key :",public_key)

  return private_key, public_key

kr_fname = "ksU2/krU2.pem"
ku_fname = "ksU2/kuU2.pem"
key_pass = "password"
if not debug:
  #key_pass  = str.encode(getpass.getpass("Please input key password for User2:"))
  key_pass  = getpass.getpass("Please input key password for User2:")


try:
  private_keyRead, public_keyRead = readKeys(kr_fname=kr_fname, ku_fname=ku_fname, passwd=key_pass)
except IOError:
  print("Reading keys failed")

if debug:
  print("Private Key:",private_keyRead)
  print("Public Key :",public_keyRead)

subject = issuer = x509.Name([
  x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
  x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Florida"),
  x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coral Gables"),
  x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of Miami"),
  x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ECE Dept"),
  x509.NameAttribute(NameOID.COMMON_NAME, u"User2"),]
)

builder = x509.CertificateBuilder()

builder = builder.subject_name(subject)
builder = builder.issuer_name(issuer)

builder = builder.not_valid_before(datetime.datetime.today() - one_day)
builder = builder.not_valid_after(datetime.datetime(2019, 12, 30))

builder = builder.serial_number(x509.random_serial_number())

builder = builder.public_key(public_keyRead)

builder = builder.add_extension(
  x509.BasicConstraints(ca=False, path_length=None),
  critical=True
)

certificate = builder.sign(
  private_key=private_keyRead,
  algorithm=hashes.SHA256(),
  backend=default_backend()
)

cert_name = "U2_cert.pem"
with open(cert_name, "wb") as file:
  file.write(certificate.public_bytes(serialization.Encoding.PEM))

'''
  || @changelog
  || | 1.0 2019-11-20 - big_nate1234 : Initial Public Release
  || #
'''
