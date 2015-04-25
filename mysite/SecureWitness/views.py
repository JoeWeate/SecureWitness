from django.http import HttpResponseRedirect, Http404
from django.core.urlresolvers import reverse

# Create your views here.
from django.http import HttpResponse
from django.shortcuts import redirect, get_object_or_404
from SecureWitness.models import Report, Document, Folder, UserProfile

from django.contrib.auth.models import User, Group, Permission
from SecureWitness.forms import DocumentForm, ReportForm, GroupForm, UserForm, AddUserForm, EditForm, FolderForm, ReactivateUserForm, SelectReportForm, LoginForm

from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib.auth import login as auth_login
from django.contrib.auth import authenticate

from django.shortcuts import render, render_to_response
from django.template import RequestContext
import datetime


from SecureWitness.hybridencryption import encrypt_file
from Crypto.PublicKey import RSA
import os, random, struct
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from django.db import models
from django.core.files import File


from django.core.mail import send_mail
import hashlib, datetime, random
from django.utils import timezone

from django.views.decorators.csrf import csrf_exempt

@login_required
def index(request):
	if not request.user.is_authenticated():
		return redirect('/accounts/login/')
	else:
		current_user = request.user
		report_list = Report.objects.filter(author = request.user).order_by('-pub_date')
		edit_report_form = SelectReportForm(report_list)
		folder_list = Folder.objects.filter(owner = request.user).order_by('-pub_date')
	return render(request,'SecureWitness/index.html',{'edit_report_form': edit_report_form, 'report_list': report_list,'current_user': current_user,'folder_list':folder_list})

#@csrf_exempt
def login(request):
	context = RequestContext(request)
	print(context)
	#c = RequestContext(request, {'next': '/SecureWitness/'})
	if request.method == 'POST':
		
		login_form = LoginForm(data=request.POST)
		if login_form.is_valid():
			username = request.POST['username']
			password = request.POST['password']

			user = authenticate(username=username, password=password)

			if user is not None:
					if user.is_active:
						auth_login(request, user)
						return render_to_response('accounts/login.html', context)
					else:
						return HttpResponse('Invalid User')
			else:
				return HttpResponse("Invalid Login Info")

	else:
		login_form = LoginForm()

	return render_to_response('SecureWitness/login.html', 
								context)

def register(request):
	# Like before, get the request's context.
	context = RequestContext(request)

	# A boolean value for telling the template whether the registration was successful.
	# Set to False initially. Code changes value to True when registration succeeds.
	registered = False

	# If it's a HTTP POST, we're interested in processing form data.
	if request.method == 'POST':
		# Attempt to grab information from the raw form information.
		# Note that we make use of both UserForm and UserProfileForm.
		user_form = UserForm(data=request.POST)
		

		# If the two forms are valid...
		if user_form.is_valid():
			# Save the user's form data to the database.
			user = user_form.save()

			# Now we hash the password with the set_password method.
			# Once hashed, we can update the user object.
			user.set_password(user.password)
			user.save()

			username = user_form.cleaned_data['username']
			email = user_form.cleaned_data['email']
			random_string = str(random.random()).encode('utf8')
			salt = hashlib.sha1(random_string).hexdigest()[:5]
			salted = (salt + email).encode('utf8')
			activation_key = hashlib.sha1(salted).hexdigest()
			key_expires = datetime.datetime.today() + datetime.timedelta(2)

			# Create and save user profile                                                                                                                                  
			new_profile = UserProfile(user=user, activation_key=activation_key, 
				key_expires=key_expires)
			new_profile.save()

			# Send email with activation key
			email_subject = 'Account confirmation'
			email_body = "Hey %s, thanks for signing up. To activate your account, click this link within \
			48hours http://127.0.0.1:8000/SecureWitness/confirm/%s" % (username, activation_key)

			send_mail(email_subject, email_body, 'ianzheng3240@gmail.com',
				[email], fail_silently=False)
			# Now sort out the UserProfile instance.
			# Since we need to set the user attribute ourselves, we set commit=False.
			# This delays saving the model until we're ready to avoid integrity problems.



			# Update our variable to tell the template registration was successful.
			registered = True

		# Invalid form or forms - mistakes or something else?
		# Print problems to the terminal.
		# They'll also be shown to the user.
		else:
			print(user_form.errors)

	# Not a HTTP POST, so we render our form using two ModelForm instances.
	# These forms will be blank, ready for user input.
	else:
		user_form = UserForm()


	# Render the template depending on the context.
	return render_to_response(
			'SecureWitness/register.html',
			{'user_form': user_form, 'registered': registered},
			context)
	output="Author: "+p.author+"Published date: "+str(p.pub_date)+'\n'+"Content: "+p.content+'\n'
	return HttpResponse(output)

@login_required
def list(request):
	# Handle file upload
	current_user = request.user
	if request.method == 'POST':
		form = DocumentForm(request.POST, request.FILES)
		if form.is_valid():

			#Plain Text Reader Instantiation
			inputFile  = request.FILES['docfile']
			inputFile.open('rb')
			inputLines = inputFile.readlines()
	
			#Encrypted File Writer Instantiation
			outputfilename = 'SecureWitness/' + inputFile.name + '.enc'
			outwriter  = open(outputfilename, 'wb')

		
			#Crypto characteristic generation
			key        = 'aaaaaaaaaaaaaaaa'
#           RSAkey     = RSA.generate(2048)
			iv         = 'bbbbbbbbbbbbbbbb'
			encryptor  = AES.new(key, AES.MODE_CBC, iv)
			filesize   = inputFile.size
			
			#Write basics
			outwriter.write((struct.pack('<Q', filesize)))
			outwriter.write(bytes(iv, 'utf-8'))
			outwriter.write(key.encode('utf-8'))
			#outwriter.write(RSA.exportKey('PEM'))
			
			#Need to sign the file
			#cipher = PKCS1_v1_5.new(RSAkey)            
#           msg = SHA256.new(RSAkey)
			#signature = cipher.sign(RSAkey)
			#outwriter.write(signature.encode('utf-8'))
		
			#Write the encrypted file
			for line in inputLines:
				if len(line) == 0:
					break
				elif len(line)%16 != 0:
					line += (' ' * (16 - len(line)%16)).encode('utf-8')
				outwriter.write(encryptor.encrypt(line))        

			#Cannot save unless the file is open in read mode
			outwriter.close()
			outwriter = open(outputfilename, 'rb')
			outputFile = File(outwriter)
			newdoc = Document(docfile = outputFile, encrypted = True, sign = False)
		
			#Save the object to the database and close the open files
			newdoc.author = current_user
			newdoc.name = request.POST['name']  
			newdoc.save()
			outwriter.close()
			inputFile.close()

			#Generate name for a signature file 
			signFileName = request.FILES['docfile'].name + '.pem'
			
			#Write the signature file with the private key
			with open(signFileName, 'wb') as signer:
				#privKey = RSAkey
				#pubKey = privKey.publickey()
				#cipher = PKCS1_v1_5.new(privKey)
				#msg = SHA256.new(RSAkey)
				#signature = signer.sign(msg)
				signer.write(key.encode('utf-8'))
	
			#Save the object to the database and close the open files   
			newdoc.save()
			outwriter.close()
		#   inputFile.close()


			#Reopen the signature file as a readable in order to push it to the database 
			#####LIKELY we want to change this to not allow uploading of the signature file to the same place as the encrypted file, as that would be a security hole I think
			with open(signFileName, 'rb') as signer:
				signedFile = File(signer)
				signatureFile = Document(docfile=signedFile, encrypted=True, sign = True)
				signatureFile.author = current_user
				signatureFile.name = request.POST['name']
				signatureFile.save()
				
	#       # Redirect to the document list after POST
			return HttpResponseRedirect(reverse('SecureWitness.views.list'))
	else:
		form = DocumentForm() # A empty, unbound form

	# Load documents for the list page
	documents = Document.objects.all()

	# Render list page with the documents and the form
	return render_to_response(
		'SecureWitness/list.html',
		{'documents': documents, 'form': form},
		context_instance=RequestContext(request)
	)

def register_confirm(request, activation_key):
	#check if user is already logged in and if he is redirect him to some other url, e.g. home
	if request.user.is_authenticated():
		HttpResponseRedirect('/SecureWitness')

	# check if there is UserProfile which matches the activation key (if not then display 404)
	user_profile = get_object_or_404(UserProfile, activation_key=activation_key)

	#check if the activation key has expired, if it hase then render confirm_expired.html
	if user_profile.key_expires < timezone.now():
		return render_to_response('SecureWitness/confirm_expired.html')
	#if the key hasn't expired save user and set him as active and render some template to confirm activation
	user = user_profile.user
	user.is_active = True
	user.save()
	return render_to_response('SecureWitness/confirm.html')

# View for creating a group, no permissions, current user added to group
@login_required
def groupCreate(request):
	context = RequestContext(request)
	current_user = request.user
	group_form = GroupForm()
	return render_to_response('SecureWitness/groupcreate.html', {'group_form': group_form, 'current_user': current_user}, context)

# View for displaying all groups current user is in
@login_required
def groupList(request):
	context = RequestContext(request)
	current_user = request.user
	group_list = current_user.groups.all()
	return render_to_response('SecureWitness/groupList.html', {'group_list': group_list, 'current_user': current_user}, context)

# View for displaying details of groups including reports associated with group, members of group
@login_required
def groupView(request, group_id):
	context = RequestContext(request)
	current_user = request.user
	try:
		group = Group.objects.get(pk=group_id)
		group_members = group.user_set.all()
		reports = Report.objects.filter(groups=group)
	except Report.DoesNotExist:
		raise Http404("Report does not exist")
	if request.method == 'POST':
		user = User.objects.get(pk=request.POST['users'])
		group.user_set.add(user)
	add_user_form = AddUserForm()
	return render_to_response('SecureWitness/groupView.html', {'current_user': current_user, 'group': group, 'group_members': group_members, 'reports': reports, 'add_user_form': add_user_form}, context)

# View displayed after succesfully creating a new group
@login_required
def groupSuccess(request):
	context = RequestContext(request)
	current_user = request.user
	group_form = GroupForm(data=request.POST)
	if group_form.is_valid():
		group = group_form.save()
		current_user.groups.add(group)
	else:
		print(group_form.errors)
	return render_to_response('SecureWitness/groupSuccess.html', {'group': group}, context)

@login_required
def editReport(request):
	current_user = request.user
	report_id = request.POST['report']
	try:
		report = Report.objects.get(pk=report_id)
	except Report.DoesNotExist:
		raise Http404("Report does not exist")
	context = RequestContext(request)
	edit_form = EditForm(current_user,instance=report)
	return render_to_response('SecureWitness/editReport.html', {'edit_form':edit_form, 'report':report}, context)

@login_required
def create(request):
	context = RequestContext(request)
	current_user = request.user
	# documents = Document.objects.filter(author=current_user)
	report_form = ReportForm(current_user, initial = {'author':current_user, 'inc_date':datetime.datetime.today})
	return render_to_response('SecureWitness/create.html', {'report_form':report_form}, context)

@login_required
def createSuccess(request):
	context = RequestContext(request)
	current_user = request.user
	documents = Document.objects.filter(author=current_user)
	report_form = ReportForm(documents, data = request.POST)
	report = report_form.save()
	return render(request, 'SecureWitness/success.html')

@login_required
def success(request):
	current_user = request.user
	if request.POST:
		edit_form = EditForm(current_user, data = request.POST)
	if edit_form.is_valid():
		edit_form.save()
	return render(request, 'SecureWitness/success.html')

@login_required
def delete(request,report_id):
	try:
		report = Report.objects.get(pk=report_id)
		report.delete()
	except Report.DoesNotExist:
		raise Http404("Report does not exist")
	return render(request, 'SecureWitness/success.html')

@login_required
def folder(request,folder_id):
	try:
		folder = Folder.objects.get(id=folder_id)
	except Report.DoesNotExist:
		raise Http404("Report does not exist")
	report_list = folder.reports.all
	context = RequestContext(request)
	current_user = request.user
	if request.POST:
		folder_form = FolderForm(current_user,request.POST, instance=folder)
		if folder_form.is_valid():
			folder_form.save()
			return redirect('/SecureWitness/success')
	else:
		folder_form = FolderForm(current_user,instance=folder)
	return render_to_response('SecureWitness/folder.html',{'folder':folder,'report_list':report_list,'folder_form':folder_form, 'folder_id':folder_id},context)

@login_required
def createFolder(request):
	current_user = request.user
	context = RequestContext(request)
	folder_form = FolderForm(current_user, initial = {'owner':request.user})
	return render_to_response('SecureWitness/createFolder.html', {'folder_form':folder_form},context)

@login_required
def folderSuccess(request):
	current_user = request.user
	folder_form = FolderForm(current_user,data=request.POST)
	#if folder_form.is_valid():
	folder = folder_form.save()
	return render(request, 'SecureWitness/folderSuccess.html')

@login_required
def folderDelete(request,folder_id):
	try:
		folder = Folder.objects.get(pk=folder_id)
		folder.delete()
	except Report.DoesNotExist:
		raise Http404("Report does not exist")
	return render(request, 'SecureWitness/success.html')

# View for displaying all reports in SecureWitness, 
# accessible only to admin users
@login_required
def viewAllReports(request):
	context = RequestContext(request)
	current_user = request.user
	reports = Report.objects.all()
	return render_to_response('SecureWitness/viewAllReports.html', {'current_user': current_user, 'reports': reports}, context)

# View for adding admin ability to existing user
# accessible only to admin users
@login_required
def addAdmin(request):
	context = RequestContext(request)
	current_user = request.user
	admins = Group.objects.get(name='admins')
	members = admins.user_set.all()
	if request.method == 'POST':
		user = User.objects.get(pk=request.POST['users'])
		admins.user_set.add(user)
	add_user_form = AddUserForm()
	return render_to_response('SecureWitness/addAdmin.html', {'current_user': current_user, 'add_user_form': add_user_form, 'admins': admins, 'members': members}, context)

@login_required
def suspendUser(request):
	context = RequestContext(request)
	current_user = request.user
	suspended, created = Group.objects.get_or_create(name="suspended")
	members = suspended.user_set.all()
	if request.method == 'POST':
		user = User.objects.get(pk=request.POST['users'])
		user.is_active = False
		user.save()
		suspended.user_set.add(user)
	add_user_form = AddUserForm()
	return render_to_response('SecureWitness/suspendUser.html', {'current_user': current_user, 'add_user_form': add_user_form, 'members': members}, context)

@login_required
def reactivateUser(request):
	context = RequestContext(request)
	current_user = request.user
	suspended, created = Group.objects.get_or_create(name="suspended")
	members = suspended.user_set.all()
	if request.method == 'POST':
		user = User.objects.get(pk=request.POST['users'])
		user.is_active = True
		user.save()
		suspended.user_set.remove(user)
	reactivate_user_form = ReactivateUserForm(members)
	return render_to_response('SecureWitness/reactivateUser.html', {'current_user': current_user, 'reactivate_user_form': reactivate_user_form, 'members': members}, context)

def search(request):
    if 'q' in request.GET and request.GET['q']:
        q = request.GET['q']
        r1 = Report.objects.filter(short__icontains=q)
        r2 = Report.objects.filter(short__icontains=q)
        reports = r1 | r2
        return render(request, 'SecureWitness/search_results.html', {'reports': reports, 'query': q})
    else:
        return HttpResponse('No results found. Please try another search term.')
