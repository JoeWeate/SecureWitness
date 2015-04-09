from django.http import HttpResponseRedirect, Http404
from django.core.urlresolvers import reverse

# Create your views here.
from django.http import HttpResponse
from django.shortcuts import redirect
from SecureWitness.models import Report, Document
from SecureWitness.forms import DocumentForm, ReportForm, GroupForm, UserForm

from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib.auth import login

from django.shortcuts import render, render_to_response
from django.template import RequestContext
import datetime


def index(request):
    if not request.user.is_authenticated():
        return redirect('/accounts/login/')
    else:
        current_user = request.user
        report_list = Report.objects.filter(author = request.user).order_by('-pub_date')
    return render(request,'SecureWitness/index.html',{'report_list': report_list,'name': name})


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

def list(request):
	# Handle file upload
	if request.method == 'POST':
		form = DocumentForm(request.POST, request.FILES)
		if form.is_valid():
			newdoc = Document(docfile = request.FILES['docfile'])
			newdoc.save()

			# Redirect to the document list after POST
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

# View for creating a group, no permissions, current user added to group
def groupCreate(request):
    context = RequestContext(request)
    current_user = request.user
    group_form = GroupForm()
    return render_to_response('SecureWitness/groupCreate.html', {'group_form': group_form, 'current_user': current_user}, context)

def groupSuccess(request):
    context = RequestContext(request)
    current_user = request.user
    group_form = GroupForm(data=request.POST)
    if group_form.is_valid():
        group = group_form.save()
        current_user.groups.add(group)
    return render_to_response('SecureWitness/groupSuccess.html', {'group': group}, context)


def detail(request, report_id):
    try:
        report = Report.objects.get(pk=report_id)
    except Report.DoesNotExist:
        raise Http404("Report does not exist")
    context = RequestContext(request)
    if request.POST:
        edit_form = EditForm(request.POST, instance=report)
        if edit_form.is_valid():
            edit_form.save()
            return redirect('/SecureWitness/success')
    else:
        edit_form = EditForm(instance=report)
    return render_to_response('SecureWitness/detail.html', {'edit_form':edit_form, 'report':report}, context)

def create(request):
    context = RequestContext(request)
    current_user = request.user
    report_form = ReportForm(initial = {'author':current_user, 'inc_date':datetime.datetime.today})
    return render_to_response('SecureWitness/create.html', {'report_form':report_form}, context)

def createSuccess(request):
    context = RequestContext(request)
    report_form = ReportForm(data = request.POST)
    if report_form.is_valid():
        report = report_form.save()
    return render(request, 'SecureWitness/success.html')

def success(request):
    return render(request, 'SecureWitness/success.html')

def delete(request,report_id):
    try:
        report = Report.objects.get(pk=report_id)
        report.delete()
    except Report.DoesNotExist:
        raise Http404("Report does not exist")
    return render(request, 'SecureWitness/success.html')
