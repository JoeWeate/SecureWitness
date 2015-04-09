from django.contrib.auth.models import User
from SecureWitness.models import Report
from django import forms

class UserForm(forms.ModelForm):
	password = forms.CharField(widget=forms.PasswordInput())

	class Meta:
		model = User
		fields = ('username', 'email', 'password', 'first_name', 'last_name')

class DocumentForm(forms.Form):
	docfile = forms.FileField(
		label='Select a file',
		help_text='max. 42 megabytes'
	)

class ReportForm(forms.ModelForm):
	class Meta:
		model = Report
		fields = ('inc_date', 'author', 'short', 'detailed', 'privacy', 'doc', 'location')
		widgets = {'author':forms.HiddenInput()}

class EditForm(forms.ModelForm):
	class Meta:
		model = Report
		fields = ('author', 'inc_date', 'short', 'detailed', 'privacy', 'doc', 'location')
		widgets = {'author':forms.HiddenInput()}