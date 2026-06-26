from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import os
import secrets

class Encrypt_Keeper:

    def __init__(self, key = None):
        #initialization requires 256 bit key. Can be a 256 bit user specified key, or None(Default) which loads from .env

        if key is None:
            key_base64 = os.getenv('ENCRYPTION_KEY')
            if not key_base64:
                raise ValueError("No value set for ENCRYPTION_KEY in environment")
            self.master_key = base64.b64decode(key_base64)
        else:
            self.master_key = key

        if len(self.master_key) != 32:
            raise ValueError("Key should be length 32, 256 bit")

        #initialize cipher
        self.cipher = AESGCMSIV(self.master_key)



    def _derive_nonce(self, plaintext):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=12,  # GCM-SIV requires 12-byte nonce
            salt=b'nonce-derivation-salt',
            info=b'deterministic-encryption',
        )
        
        nonce = hkdf.derive(plaintext.encode())
        return nonce

    def encrypt(self, plaintext):
        if not plaintext:
            return None
        
        nonce = self._derive_nonce(plaintext)

        ciphertext = self.cipher.encrypt(nonce, plaintext.encode(), None)
        combined = nonce + ciphertext

        return base64.b64encode(combined).decode('utf-8')

    def decrypt(self, ciphertext_b64):
        combined = base64.b64decode(ciphertext_b64)

        nonce = combined[:12]
        ciphertext = combined[12:]

        plaintext = self.cipher.decrypt(nonce, ciphertext, None)
        
        return plaintext.decode('utf-8')

   


 
    def mask_ip(self, ip_address):
       #Mask:
       #192.168.1.123  -> 192.168.0.0
       #2001:db8:abcd:1234::1 -> 2001:db8:abcd::

       
        if not ip_address:
            return None

        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)

            if ip.version == 4:
                parts = ip_address.split(".")
                return f"{parts[0]}.{parts[1]}.0.0"
            else:
                network = ipaddress.ip_network(f"{ip}/48", strict=False)
                return str(network.network_address)

        except ValueError:
            return None


    #Generate a new 256-bit encryption key.
    def generate_key():
        key = secrets.token_bytes(32)
        return base64.b64encode(key).decode('utf-8')

    #When run directly i.e. python3 Encrypt_Keeper.py 
    if __name__ == "__main__":
        print(f"ENCRYPTION_KEY={generate_key()}")
        print("\n Save this key securely! If lost, encrypted data cannot be recovered.")
        print("Add this line to your .env file.\n")
