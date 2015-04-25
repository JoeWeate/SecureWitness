import requests
import json
import sys

loginurl = "http://127.0.0.1:8000/accounts/login/"
checkurl = 'http://127.0.0.1:8000/SecureWitness/remotelogin/'


if __name__ == "__main__":
	
	username = input("What is your username: ")
	password = input("What is your password: ")


	client = requests.session()

	r0 = client.get(loginurl)
	cookies = dict(client.cookies)
	token = client.cookies['csrftoken']

	logindata = {'username': username, 'password': password, 'csrfmiddlewaretoken': token, 'next': '/'}
	
	r1 = requests.post(loginurl, data = logindata, headers = dict(Referer=loginurl), cookies=cookies)

	print(r1.status_code)