import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
import pickle

key_length = 2048

msg = "Human Rights Violation"

privKey = RSA.generate(key_length)
pubKey  = privKey.publickey()

emsg = pubKey.encrypt(msg.encode('utf-8'), 32)

dmsg = privKey.decrypt(emsg)
print(msg)
print(dmsg)

##################################################################
###############Testing the encryption of a file###################
##################################################################

def readfile(filename):
	fh = open(filename, 'rb')
	string = fh.read()
	fh.close()
	return string

def readnonbytefile(filename):
	fh = open(filename, 'r')
	string = fh.read()
	fh.close()
	return string

def writefile(filename, string):
	fh = open(filename, 'wb')
	fh.write(string)
	fh.close()

def write_serial(filename, data):
	fh = open(filename, 'wb')
	pickle.dump(data, fh, protocol=pickle.HIGHEST_PROTOCOL)
	fh.close()

def read_serial(filename):
	fh = open(filename, 'rb')
	data = pickle.load(fh)
	fh.close()
	return data


plaintext = readfile('testtext.txt')
#h = SHA256.new(plaintext)
#signer = PKCS1_OAEP.new(privKey, h)
#signature = signer.encrypt(h)

#Save signature to file
#write_serial('signature.pk1', signer)

#Encrypt the file
write_serial('encryptedfile.pk1', pubKey.encrypt(plaintext, ''))

#Read the file back
encodedfile = read_serial('encryptedfile.pk1')
plaindata = privKey.decrypt(encodedfile[-1])

#Verify author
#h = SHA256.new(plaindata)
print(plaindata)
print('')
writefile('dfile.txt', plaindata)
print(readfile('dfile.txt'))
print('')
#print(privKey.decrypt(pubKey.encrypt(plaintext.encode('utf-8'), '')).decode('utf-8'))

#verifier = PKCS1_OAEP.new(privKey, h)
#signature = read_serial('signature.pk1')
#if verifier.verify(h, signature):
#	print("Yay!")
#	print(plaindata)
#else:
#	print("Wrong signature")

