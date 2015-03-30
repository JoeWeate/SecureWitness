#import pycrypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_RSA(public_key_loc, msg):
	#
	#param: public_key_loc Path to public key
	#paraL msg is string to be encrypted
	#return base64 encoded encrypted string
	#

	key = open(public_key_loc, "r").read()
	rsakey = RSA.importKey(key)
	rsakey = PKCS1_OAEP.new(rsakey)
	encrypted = rsakey.encrypt(msg)
	return encrypted.encode("base64")

if __name__ == "__main__":
	key = RSA.generate(2048)
	privKey = key.exportKey('DER')
	pubKey   = key.publickey().exportKey('DER')

	privKeyObj = RSA.importKey(privKey)
	pubKeyObj  = RSA.importKey(pubKey)

	msg = "Human Rights Violation"
	emsg = pubKeyObj.encrypt(msg, 'x')[0]
	dmsg = privKeyObj.decrypt(emsg)

	assert(msg == dmsg)
