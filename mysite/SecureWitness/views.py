from django.shortcuts import render
from django.http import Http404

# Create your views here.
from django.http import HttpResponse
from SecureWitness.models import Report
from django.template import RequestContext, loader


def index(request):
	if not request.user.is_authenticated():
		return render(request, 'SecureWitness/login_error.html')
	else:
		report_list = Report.objects.order_by('-pub_date')[:5]
		return render(request,'SecureWitness/index.html',{'report_list': report_list})

def login(request):
	return render(request, 'SecureWitness/login.html')

def detail(request, report_id):
	try:
		report = Report.objects.get(pk=report_id)
	except Report.DoesNotExist:
		raise Http404("Question does not exist")
	return render(request, 'SecureWitness/detail.html', {'report':report})

def login(request):
	return render(request, 'SecureWitness/login.html')