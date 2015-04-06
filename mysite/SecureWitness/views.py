from django.shortcuts import render
from django.http import Http404
from datetime import datetime

# Create your views here.
from django.http import HttpResponse
from SecureWitness.models import Report, Folder
from django.template import RequestContext, loader


def index(request):
	if not request.user.is_authenticated():
		return render(request, 'SecureWitness/login_error.html')
	else:
		folder_list = Folder.objects.filter(author = request.user.username)
		report_list = Report.objects.filter(author = request.user.username).order_by('-pub_date')[:5]
		return render(request,'SecureWitness/index.html',{'report_list': report_list, 'folder_list': folder_list})

def login(request):
	return render(request, 'SecureWitness/login.html')

def logout(request):
	return render(request, 'SecureWitness/logout.html')

def detail(request, report_id):
	try:
		report = Report.objects.get(pk=report_id)
	except Report.DoesNotExist:
		raise Http404("Question does not exist")
	return render(request, 'SecureWitness/detail.html', {'report':report})

def create_report(request):
	report = Report(author = request.user.username, pub_date= datetime.now(), content = request.GET['content'])
	report.save()
	return HttpResponse('success')

def edit_report(request):
	report = Report.objects.get(id = request.GET['author'])
	report.content = request.GET['content']
	report.pub_date = datetime.now()
	report.save()
	return HttpResponse('report edited!')