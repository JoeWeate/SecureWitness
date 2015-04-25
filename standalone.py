import requests
#import json


loginurl = "http://127.0.0.1:8000/accounts/login"
checkurl = 'http://127.0.0.1:8000/SecureWitness/remotelogin'

if __name__ == "__main__":
	
	username = input("What is your username: ")
	password = input("What is your password: ")

	#r0 = requests.get(loginurl)
	#csrftoken = r0.cookies['csrftoken']

	#logindata = {'username': username, 'password': password, 'csrfmiddlewaretoken': csrftoken}

	rcheck = requests.get(checkurl)
	checklogin = {'username': username, 'password': password}	
#	jsonparams = json.dumps(logindata)
#	headers = {'Content-Type': 'SecureWitness/json'}

	r1 = requests.post(checkurl, data=checklogin)

	print(rcheck.status_code)
	print(rcheck.content)
	print(r1.status_code)
