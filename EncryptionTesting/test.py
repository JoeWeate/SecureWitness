import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Hash import MD5

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

inputfile = open('testtext.txt', 'r')
output = open('encryptedtext.txt', 'wb')

#
for line in inputfile:
	print(line)
	#line = line
	emsg = pubKey.encrypt(bytes(line, 'utf-8'), 32)
	
	#print (emsg)

	output.write(emsg[0])

######################################



inputfile.close()
output.close()

inputfile = open('encryptedtext.txt', 'rb')
output = open('decryptedtext.txt', 'w')

for line in inputfile:
	#line = bytes(line, 'utf-8')
	#temp = (line[0, len(line)-1], None)
	#dmsg = privKey.decrypt(line[0, -1])
	print(line)

	print('')
	dmsg = privKey.decrypt(line)
	print(dmsg)
	print('')
	dmsg = dmsg.decode('utf-8')
	print(dmsg)
	print('')

inputfile.close()
output.close()
