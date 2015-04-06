import os, random, struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random




#encrypt a file
def encrypt_file(key, infile, outfile=None, chunksize=64*1024):
	if not outfile:
		outfile = infile + ".enc"

	iv = 'ffffddddccccbbbb'
	#iv = ''.join(chr(random.randint(0,0xFF)) for i in range(16))
	#print(len(iv))
	#print(iv)
	encryptor = AES.new(key, AES.MODE_CBC, iv)
	filesize = os.path.getsize(infile)

	with open(infile, 'rb') as inp:
		with open(outfile, 'wb') as output:
			output.write((struct.pack('<Q', filesize)))
			output.write(bytes(iv, 'utf-8'))

			while True:
				chunk = inp.read(chunksize)
				if len(chunk) == 0:
					break
				elif len(chunk)%16 != 0:
					chunk += (' ' * (16- len(chunk)%16)).encode('utf-8')
				output.write(encryptor.encrypt(chunk))

def decrypt_file(key, infile, outfile=None, chunksize = 24*1024):
	if not outfile:
		outfile = os.path.splitext(infile)[0]

	with open(infile, 'rb') as inp:
		origsize = struct.unpack('<Q', inp.read(struct.calcsize('Q')))[0]
		iv = inp.read(16).decode('utf-8')
		decryptor = AES.new(key, AES.MODE_CBC, iv)

		with open(outfile, 'wb') as output:
			while True:
				chunk = inp.read(chunksize)
				if len(chunk) == 0:
					break
				output.write(decryptor.decrypt(chunk))

			output.truncate(origsize)
		

#BASE_DIR = os.path.dirname(os.path.abspath(__file__)))
#ENCRYP_DIR = os.path.join(BASE_DIR, "encrypted.txt")

if __name__ == "__main__":

	encrypt_file('aaaaaaaaaaaaaaaa', 'testtext.txt', 'output.txt')
	decrypt_file('aaaaaaaaaaaaaaaa', 'output.txt'  , 'decrypted.txt')

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
		
