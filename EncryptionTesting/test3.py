import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

#BASE_DIR = os.path.dirname(os.path.abspath(__file__)))
#ENCRYP_DIR = os.path.join(BASE_DIR, "encrypted.txt")

if __name__ == "__main__":
	privKey = RSA.generate(2048)
	pubKey  = privKey.publickey()

	cipher = PKCS1_v1_5.new(pubKey)

	
	encryptedbytes = b''#cipher.encrypt("Hello!".encode('utf-8'))
	with open("testtext.txt", 'r') as f:
		ef = open("encryptedfile3.txt", 'wb')
		for line in f:
			encryptedbytes = cipher.encrypt(line.encode('utf-8'))
			ef.write(encryptedbytes)
		ef.close()
		#cipher.encrypt(encryptedbytes.encode('utf-8'))
	#Write to a file
	print('Writing to file')

#	with open("encryptedfile3.txt", 'wb') as f:
#		f.write(encryptedbytes)


	with open("encryptedfile3.txt", 'rb') as f:
		privCipher = PKCS1_v1_5.new(privKey)
		for line in f:
			string = privCipher.decrypt(line, -1)
			print(string)
