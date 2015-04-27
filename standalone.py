import requests
import json
import sys
from hybridencryption import encrypt_file as encrypt
from hybridencryption import decrypt_file as decrypt
import random
from Crypto.PublicKey import RSA
import os, random, struct
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
import string
import os
from base64 import b64encode as encode
from base64 import b64decode as decode

checkurl = 'http://127.0.0.1:8000/SecureWitness/login/'
loginurl = 'http://127.0.0.1:8000/accounts/login/'

cmdurl = 'http://127.0.0.1:8000/SecureWitness/execute/'


if __name__ == "__main__":
	
	#Ask for login
	username = input("What is your username: ")
	password = input("What is your password: ")


	client = requests.session()

	r0 = client.get(loginurl)
	cookies = dict(client.cookies)
	token = client.cookies['csrftoken'] 

	logindata = {'username': username, 'password': password, 'csrfmiddlewaretoken': token, 'next': '/'}
	
	r1 = client.post(checkurl, data = logindata, headers = dict(Referer=checkurl))

	print(r1.content.decode('utf-8'))

	if r1.status_code == 200 and r1.content != 'Invalid Login Info'.encode('utf-8'):
		while(True):
			r = client.get(cmdurl)
			token = r.cookies['csrftoken']
			command = input("\nEnter command: ")

			if command == "ls -pub":
				print("Showing all public files")
				payload = {'filter': 'pub', 'csrfmiddlewaretoken': token, 'next': '/SecureWitness/execute/'}
				r = client.post(cmdurl, data = payload, cookies = cookies)
				print(r.content.decode('utf-8'))

			elif command == 'ls -m':
				payload = {'filter': 'authored', 'csrfmiddlewaretoken': token, 'next': '/SecureWitness/execute/'}
				r = client.post(cmdurl, data = payload, cookies = cookies)
				print(r.content.decode('utf-8'))

			elif command == "ls -a":
				print("Showing all shared files")

			elif command == "ls -priv":
				print("Showing all shared private files")
				payload = {'filter': 'priv', 'csrfmiddlewaretoken': token, 'next': '/SecureWitness/execute/'}
				r = client.post(cmdurl, data = payload, cookies = cookies)
				print(r.content.decode('utf-8'))		

			elif command == 'ls -d':
				payload = {'filter': 'dirs', 'csrfmiddlewaretoken': token, 'next': '/SecureWitness/execute/'}
				r = client.post(cmdurl, data = payload, cookies = cookies)
				print(r.content.decode('utf-8'))		

			# elif command == 'groups':
			# 	payload = {'filter': 'groups', 'csrfmiddlewaretoken': token, 'next': '/SecureWitness/execute/'}
			# 	r = client.post(cmdurl, data = payload, cookies = cookies)
			# 	print(r.content.decode('utf-8'))		


			elif command == "get":
				reportname = input("What report would you like to access: ")
				payload = {'filter': 'haveaccess', 'csrfmiddlewaretoken': token, 'next': '/SecureWitness/execute/', 'report': reportname}
				r = client.post(cmdurl, data = payload, cookies = cookies)
				print(r.content.decode('utf-8'))	

				filename = input('What file would you like: ')
				payload = {'filter': 'download', 'csrfmiddlewaretoken': token, 'next': '/SecureWitness/execute/', 'report': reportname, 'filename': filename}
				r = client.post(cmdurl, data = payload, cookies = cookies)
				url = r.content.decode('utf-8').split(', ')
				print(url)
				downloadurls = []

				for link in url:
					downloadurls.append('http://127.0.0.1:8000' + link)

				print(downloadurls)

				saveloc = input("Enter location to save to with a backslash at the end: ")
				for link in downloadurls:
					
					savename = saveloc + link.split('/')[-1]
					r = client.get(link, stream=True)

					with open(savename, 'wb') as downloader:
						for chunk in r.iter_content(2048):
							downloader.write(chunk)

			elif command == "disp":
				reportname = input('Enter report to display: ')
				payload = {'filter': 'disp', 'csrfmiddlewaretoken': token, 'next': '/SecureWitness/execute/', 'report': reportname}
 
				r = client.post(cmdurl, data = payload, cookies = cookies)

				
				print(r.content.decode('utf-8'))

			elif command == 'encrypt':
				filepath = input('Absolute file path to local file to encrypt: ')
				saveloc  = input('Where do you want to save the encrypted file (include ending backslash): ')
				sepsigloc = input('Do you want to store the signature file in a separate place [y/N]: ')
				if sepsigloc == 'y' or sepsigloc == 'Y':
					sigsaveloc = input('Enter location to store signature file (include ending backslash): ')
				else:
					sigsaveloc = saveloc

				print(filepath)
				with open(filepath, 'rb') as inputFile:

					# inputLines = inputFile.readlines()
					# print(inputLines)
					filename = filepath.split('\\')[-1]
			
					#Encrypted File Writer Instantiation
					outputfilename = saveloc + filename + '.enc'
					outwriter  = open(outputfilename, 'wb')

					#Crypto characteristic generation
					key        = ''.join(random.choice(string.ascii_uppercase+string.digits) for i in range(16))
					iv         = Random.new().read(16)
					encryptor  = AES.new(key, AES.MODE_CBC, iv)
					filesize   = os.stat(filepath).st_size
					with open(outputfilename, 'wb') as outwriter:
						#Write basics
						outwriter.write((struct.pack('<Q', filesize)))
						outwriter.write(iv)
						outwriter.write(key.encode('utf-8'))
					
						#Write the encrypted file
						while True:
							chunk = inputFile.read(64*1024)
							#print(chunk)
							if len(chunk) == 0:
								break
							elif len(chunk)%16 != 0:
								chunk += bytes(('*' * (16- len(chunk)%16)), 'utf-8')
							outwriter.write(encryptor.encrypt(chunk))        

					#Generate name for a signature file 
					signFileName = sigsaveloc + filename + '.pem'
				
					#Write the signature file with the private key
					with open(signFileName, 'wb') as signer:
						signer.write(key.encode('utf-8'))

			elif command == 'decrypt':
				filename = input('Absolute file path to local file to decrypt: ')
				sigfile  = input('Absolute file path to local signature file: ')
				outfile  = input('Absolute file path with file name to save as: ')
				#saveloc  = 'C:\\Users\\n3\\Downloads\\'#input('Absolute file path to save location (including ending backslash): ')
				#checkkey = input('Key: ')
				#print(sigfile.split('\\','.')[-3])

				with open(sigfile, 'rb') as verifier:
					key = verifier.read().decode('utf-8')

					with open(filename, 'rb') as inp:
						origsize = struct.unpack('<Q', inp.read(struct.calcsize('Q')))[0]
						iv = inp.read(16)#.decode('utf-8')
						checkkey = inp.read(len(key)).decode('utf-8')
						#print(key + '    ' + checkkey)
						if key == checkkey:

							decryptor = AES.new(key, AES.MODE_CBC, iv)
					
							with open(outfile, 'wb') as output:
								while True:
									chunk = inp.read(24*1024)
									if len(chunk) == 0:
										break
									chunk = decryptor.decrypt(chunk)
									#print(chunk)
									output.write(chunk)
					
								output.truncate(origsize)

						else:
							print('Signature did not match, cannot decrypt the file for you. Please try again.')

			elif command == 'help':
				print(
					'ls\n' +
						'\t-pub:  Display all public reports\n' +
						'\t-priv: Display all private reports\n' +
						'\t-m:    Display all authored reports\n' +
						'\t-a:    Display all shared reports\n' +
						'\t-d:    Display all folders\n' +
					'encrypt: Enter process for encrypting file with AES and displaying key\n'
					'decrypt: Enter process for decrypting file with AES\n'
					'get:     Enter process for obtaining file from server'
					'exit: Exit the application'
					)
			elif command == "exit":
				break
	else:
		print("Login unsuccessful.")