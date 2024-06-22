import re
import os
import shutil
from pathlib import Path
from zipfile import ZipFile
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, pkcs12

import httpx

APK_FILE = "rewe.apk"
APK_DIR = "rewe"
MTLS_PROD = "mtls_prod.pfx"
MTLS_PASSWORD = b"NC3hDTstMX9waPPV"

def get_creds(source_path, key_filename, cert_filename):
  """Fetch the apk and extract private key and certificate.

  APK source: uptodown.com
  """
  # Get the apk. 
  FULL_APK_DIR_PATH = os.path.join(source_path, APK_DIR)
  FULL_APK_FILE_PATH = os.path.join(source_path, APK_FILE)
  FULL_MTLS_PROD_PATH = os.path.join(source_path, MTLS_PROD)
  FULL_KEY_FILE_PATH = os.path.join(source_path, key_filename)
  FULL_CERT_FILE_PATH = os.path.join(source_path, cert_filename)

  print("Starting to fetch the private.key and private.pem. This could take a moment.")
  headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", 
    "Accept-Encoding": "gzip, deflate, br, zstd", 
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6,it;q=0.5,nb;q=0.4,no;q=0.3",
    "Dnt": "1",
    "Priority": "u=0, i",
    }
  with httpx.Client(http2=True) as client:
    client.headers = headers

    url = "https://rewe.de.uptodown.com/android/post-download"
    res = client.get(url)
    pattern = r"data-url=\".+?\""
    all_data_patterns = re.findall(pattern, res.text)
    if len(all_data_patterns) == 0:
      print("couldn't find data patterns.")
      return "error"
    all_data_patterns.sort(reverse=True, key=lambda x: len(x))
    the_one = all_data_patterns[0]
    the_one = the_one.strip("data-url=").strip("\"")

    url2 = "https://dw.uptodown.com/dwn/" + the_one
    res2 = client.get(url2)
    if res2.status_code == 302:
      url3 = res2.headers["location"]
      print("Download the rewe.apk.")
      res3 = client.get(url3)
      with open(FULL_APK_FILE_PATH, "wb") as file:
        file.write(res3.content)
    else:
      print("unexpected status code: ", res2.status_code)
      return "error"

  # Unpack the apk and get mtls_prod.pfx.
  with ZipFile(FULL_APK_FILE_PATH, "r") as zipfile:
    zipfile.extractall(FULL_APK_DIR_PATH)

  print("Search for the pfx-file that holds the private key and certificate.")
  for root, dirs, files in os.walk(FULL_APK_DIR_PATH):
    if "mtls_prod.pfx" in files:
      mtls_path = os.path.join(root, "mtls_prod.pfx")
      os.rename(mtls_path, FULL_MTLS_PROD_PATH)
  shutil.rmtree(FULL_APK_DIR_PATH)
  os.remove(FULL_APK_FILE_PATH)

  # Split into private key and certificate.
  with open(FULL_MTLS_PROD_PATH, "rb") as pfx_file:
    private_key, certificate, _ = pkcs12.load_key_and_certificates(data=pfx_file.read(), password=MTLS_PASSWORD)

  key = private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
  cert = certificate.public_bytes(encoding=Encoding.PEM)

  with open(FULL_KEY_FILE_PATH, "wb") as key_file:
    key_file.write(key)
  with open(FULL_CERT_FILE_PATH, "wb") as cert_file:
    cert_file.write(cert)

  os.remove(FULL_MTLS_PROD_PATH)
  print("Finished.")
  return None

if __name__ == "__main__":
  source_path = Path(__file__).resolve().parent
  get_creds(source_path, "private_test.key", "private_test.pem")