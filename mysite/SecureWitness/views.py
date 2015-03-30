from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse
from SecureWitness.models import Report


def index(request):
    report_list = Report.objects.order_by('-pub_date')[:5]
    output = ""
    for p in report_list:
        output="Author: "+p.author+'\n'+"Published date: "+str(p.pub_date)+'\n'+"Content: "+p.content+'\n'
    return HttpResponse(output)