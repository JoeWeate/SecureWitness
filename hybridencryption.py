import os, random, struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
#from django.core.files import File





#encrypt a file
def encrypt_file(key, RSAkey, infile, outfile=None, chunksize=64*1024):
	if not outfile:
		outfile = infile + ".enc"

	iv = 'ffffddddccccbbbb'
	#iv = ''.join(chr(random.randint(0,0xFF)) for i in range(16))
	#print(len(iv))
	#print(iv)
	encryptor = AES.new(key, AES.MODE_CBC, iv)
	filesize = os.path.getsize(infile)

	with django.core.files.File.open(infile, 'rb') as inp:
		with django.core.files.File.open(outfile, 'wb') as output:
			output.write((struct.pack('<Q', filesize)))
			output.write(bytes(iv, 'utf-8'))

			while True:
				chunk = inp.read(chunksize)
				if len(chunk) == 0:
					break
				elif len(chunk)%16 != 0:
					chunk += (' ' * (16- len(chunk)%16)).encode('utf-8')
				output.write(encryptor.encrypt(chunk))

	with open('signature.pem', 'wb') as signer:
		privKey = RSAkey
		pubKey  = privKey.publickey()
		cipher  = PKCS1_v1_5.new(privKey)
		msg     = SHA256.new(key.encode('utf-8'))
		signature = cipher.sign(msg)
		signer.write(signature)
	
	return outfile, 'signature.pem'
def decrypt_file(sigfile, infile, outfile=None, chunksize = 24*1024):
	#print(chunksize)
	if not outfile:
		outfile = os.path.splitext(infile)[0]

	with open(sigfile, 'rb') as verifier:
		#part1 = verifier.read()
		#privKey = verifier.read()
		#pubKey  = privKey.publickey()
	#	cipher  = PKCS1_v1_5.new(pubKey)
#		msg     = SHA256.new(key.encode('utf-8'))

		key = verifier.read().decode('utf-8')
		
		#print (signature, " matches? ", fromfile)

#		if cipher.verify(msg, part1) :

		with open(infile, 'rb') as inp:
			origsize = struct.unpack('<Q', inp.read(struct.calcsize('Q')))[0]
			iv = inp.read(16).decode('utf-8')
			checkkey = inp.read(len(key)).decode('utf-8')

			if key == checkkey:

				decryptor = AES.new(key, AES.MODE_CBC, iv)
		
				with open(outfile, 'wb') as output:
					while True:
						chunk = inp.read(chunksize)
						if len(chunk) == 0:
							break
						output.write(decryptor.decrypt(chunk))
		
					output.truncate(origsize)

			else:
				with open(outfile, 'w') as output:
					output.write('Signature did not match, cannot decrypt the file for you. Please try again.')
		

#BASE_DIR = os.path.dirname(os.path.abspath(__file__)))
#ENCRYP_DIR = os.path.join(BASE_DIR, "encrypted.txt")

if __name__ == "__main__":
	filein = input("Enter name of encrypted file: ")
	signin = input("Enter name of signature file: ")
	#deckey = input("Enter the key that was given: ")

	#deckey = raw_input("Enter key that was provided by the owner")
	decrypt_file(signin, filein, "decrypted_output.txt")

#	RSAkey = RSA.generate(2048)
#	encrypt_file('aaaaaaaaaaaaaaaa', RSAkey, 'testtext.txt', 'output.txt')
#	decrypt_file('aaaaaaaaaaaaaaab', RSAkey, 'output.txt'  , 'decrypted.txt')

if __name__ == "__main2__":


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
		
