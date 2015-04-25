import requests
import json
import sys

loginurl = "http://127.0.0.1:8000/accounts/login/"
checkurl = 'http://127.0.0.1:8000/SecureWitness/login/'


if __name__ == "__main__":
	
	#Ask for login
	username = input("What is your username: ")
	password = input("What is your password: ")


	client = requests.session()

	r0 = client.get(checkurl)
	cookies = dict(client.cookies)
	token = client.cookies['csrftoken']

	logindata = {'username': username, 'password': password, 'csrfmiddlewaretoken': token, 'next': '/'}
	
	r1 = requests.post(checkurl, data = logindata, headers = dict(Referer=loginurl), cookies=cookies)


	if r1.status_code == 200 and r1.content != 'Invalid Login Info'.encode('utf-8'):
		print("Login successful!")
		while(True):
			command = input("Enter command\n")

			if command == "ls -pub":
				print("Showing all public files")
			elif command == "ls -a":
				print("Showing all shared files")
			elif command == "ls -priv":
				print("Showing all shared private files")
			elif command == "obtain":
				input("What file would you like: ")
			elif command == "killall":
				break
	else:
		print("Login unsuccessful.")