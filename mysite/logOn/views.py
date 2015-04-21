# import datetime,random,_sha256

# from django.shortcuts import render_to_response, get_object_or_404
# from django.core.mail import send_mail
# from django.shortcuts import render
# from logOn.models import UserProfile
# from logOn.forms import RegistrationForm
# from django import forms
# # Create your views here.
from logOn.forms import MyRegistrationForm
from django.shortcuts import render_to_response
from django.shortcuts import redirect
from django.contrib import auth
from django.core.context_processors import csrf
from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect
from django.template import RequestContext


def login(request):
    c={}
    c.update(csrf(request))
    return render_to_response('accounts/login.html',c,context_instance=RequestContext(request))

def auth_view(request):
    username= request.POST.get('username', '')
    password= request.POST.get('password', '')
    user =auth.authenticate(username=username, password=password)

    if user is not None:
        auth.login(request,user)
        return HttpResponseRedirect('/accounts/loggedin')
    else:
        return HttpResponseRedirect('/accounts/invalid')


def loggedin(request):
    return render_to_response('accounts/loggedin.html',
                              {'full_name': request.user.username })

def invalid_login(request):
    return render_to_response('accounts/invalid_login.html')

def logout(request):
    auth.logout(request)
    return render_to_response('accounts/logout.html')

def register_user(request):
    if request.method =="POST":
        form =MyRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect('/accounts/register_success')

    args={}
    args.update(csrf(request))

    args['form'] = MyRegistrationForm()

    return render_to_response('register.html',args)


def register_success(request):
    return render_to_response('register_success.html')

def home(request):
    return render_to_response('home.html')

def redirect(request):
    return HttpResponseRedirect('/SecureWitness')













# def register(request):
#     if request.user.is_authenticated():
#         # They already have an account; don't let them register again
#         return render_to_response('register.html', {'has_account': True})
#     manipulator = RegistrationForm()
#     if request.POST:
#         new_data = request.POST.copy()
#         errors = manipulator.get_validation_errors(new_data)
#         if not errors:
#             # Save the user
#             manipulator.do_html2python(new_data)
#             new_user = manipulator.save(new_data)
#
#             # Build the activation key for their account
#             salt = _sha256.new(str(random.random())).hexdigest()[:5]
#             activation_key = _sha256.new(salt+new_user.username).hexdigest()
#             key_expires = datetime.datetime.today() + datetime.timedelta(2)
#
#             # Create and save their profile
#             new_profile = UserProfile(user=new_user,
#                                       activation_key=activation_key,
#                                       key_expires=key_expires)
#             new_profile.save()
#
#             # Send an email with the confirmation link
#             email_subject = 'Your new example.com account confirmation'
#             email_body = "Hello, %s, and thanks for signing up for an \
# example.com account!\n\nTo activate your account, click this link within 48 \
# hours:\n\nhttp://example.com/accounts/confirm/%s" % (
#                 new_user.username,
#                 new_profile.activation_key)
#             send_mail(email_subject,
#                       email_body,
#                       'accounts@example.com',
#                       [new_user.email])
#
#             return render_to_response('register.html', {'created': True})
#     else:
#         errors = new_data = {}
#
#     form = forms.FormWrapper(manipulator, new_data, errors)
#     return render_to_response('register.html', {'form': form})
#
#
# def confirm(request, activation_key):
#     if request.user.is_authenticated():
#         return render_to_response('confirm.html', {'has_account': True})
#     user_profile = get_object_or_404(UserProfile,
#                                      activation_key=activation_key)
#     if user_profile.key_expires < datetime.datetime.today():
#         return render_to_response('confirm.html', {'expired': True})
#     user_account = user_profile.user
#     user_account.is_active = True
#     user_account.save()
#     return render_to_response('confirm.html', {'success': True})