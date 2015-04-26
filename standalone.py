import requests
import json
import sys

checkurl = 'http://127.0.0.1:8000/SecureWitness/login/'
loginurl = 'http://127.0.0.1:8000/accounts/login/'

cmdurl = 'http://127.0.0.1:8000/SecureWitness/execute/'


if __name__ == "__main__":
	
	#Ask for login
	username = 'ng4mf'#input("What is your username: ")
	password = 'password'#input("What is your password: ")


	client = requests.session()

	r0 = client.get(loginurl)
	cookies = dict(client.cookies)
	token = client.cookies['csrftoken']
	print(r0.cookies)

	logindata = {'username': username, 'password': password, 'csrfmiddlewaretoken': token, 'next': '/'}
	
	r1 = client.post(loginurl, data = logindata, headers = dict(Referer=loginurl))



		
			# if filt == 'dirs':
			# 	folder_list = Folder.objects.filter(owner = request.user).order_by('-pub_date')
			# elif filt == 'authored'
			# 	report_list = Report.objects.filter(author = request.user).order_by('-pub_date')			
			# elif filt == 'pub':
			# 	# Get all reports that have public access
			# 	public_list = Report.objects.filter(privacy=False)
			# elif filt == 'groups':
			# 	# Get all groups that current user is a member of
			# 	user_groups = current_user.groups.all()
			# elif filt == 'priv':
			# 	# Get all private reports that have been shared with current user by group association
			# 	shared_list = Report.objects.filter(groups__in=user_groups)
			# elif filt == 'down':
			# 	filename = request.POST['filename']
			# 	shared_list = Report.objects.filter(groups__in=user_groups)
			# 	public_list = Report.objects.filter(privacy=False)
			# 	if filename not in shared_list and filename not in public_list:
			# 		return HttpResponse("You do not have permission to access a file with this name.")
	if r1.status_code == 200 and r1.content != 'Invalid Login Info'.encode('utf-8'):
		print("Login successful!")
		while(True):
			r = client.get(cmdurl)
			token = r.cookies['csrftoken']
			command = input("\nEnter command\n")

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

			elif command == 'groups':
				payload = {'filter': 'groups', 'csrfmiddlewaretoken': token, 'next': '/SecureWitness/execute/'}
				r = client.post(cmdurl, data = payload, cookies = cookies)
				print(r.content.decode('utf-8'))		

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
				reportname = input('Enter report to display')
				payload = {'filter': 'disp', 'csrfmiddlewaretoken': token, 'next': '/SecureWitness/execute/', 'report': reportname}
 
				r = client.post(cmdurl, data = payload, cookies = cookies)

				
				print(r.content.decode('utf-8'))


			elif command == "kill":
				break
	else:
		print("Login unsuccessful.")