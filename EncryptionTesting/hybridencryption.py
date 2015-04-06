import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

#BASE_DIR = os.path.dirname(os.path.abspath(__file__)))
#ENCRYP_DIR = os.path.join(BASE_DIR, "encrypted.txt")

if __name__ == "__main__":
	privKey = RSA.generate(2048)
	pubKey  = privKey.publickey()
	cipher = PKCS1_OAEP.new(pubKey, SHA256)
	
	signaturestring = "signature"
	sentsignature = "signature"
	signature = cipher.encrypt(signaturestring.encode('utf-8'))

	with open('reportKey.pem', 'wb') as f:
		f.write(signature)

	
	with open('reportKey.pem', 'rb') as f:
		cipher2 = PKCS1_OAEP.new(privKey, SHA256)
		readsignature = f.read()
		readsignature = cipher2.decrypt(readsignature)
		readsignature = readsignature.decode('utf-8')
		print(readsignature)





	#signkey = b"This is my signature"
	#iv = Random.new().read(AES.block_size)
	#signcipher = AES.new(signkey, AES.MODE_CFB, iv)
		
