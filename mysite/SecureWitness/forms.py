from django.contrib.auth.models import User, Group, Permission
from SecureWitness.models import Report,Folder, Document, Comment, Keyword
from django import forms

class UserForm(forms.ModelForm):
	password = forms.CharField(widget=forms.PasswordInput())

	class Meta:
		model = User
		fields = ('username', 'email', 'password', 'first_name', 'last_name')

	def clean_email(self):
		email = self.cleaned_data["email"]
		try:
			User._default_manager.get(email=email)
		except User.DoesNotExist:
			return email
		raise forms.ValidationError('duplicate email')

	#modify save() method so that we can set user.is_active to False when we first create our user
	def save(self, commit=True):        
		user = super(UserForm, self).save(commit=False)
		user.email = self.cleaned_data['email']
		if commit:
			user.is_active = False # not active until he opens activation link
			user.save()

		return user

class LoginForm(forms.Form):
	username = forms.CharField(label = 'Username: ')
	password = forms.CharField(label = 'Password: ', widget = forms.PasswordInput())

class AddUserForm(forms.Form):
	def __init__(self, *args, **kwargs):
		super(AddUserForm, self).__init__(*args, **kwargs)
		self.fields['users'] = forms.ChoiceField(choices = [ (u.id, str(u)) for u in User.objects.all()])

class ReactivateUserForm(forms.Form):
	def __init__(self, members, *args, **kwargs):
		super(ReactivateUserForm, self).__init__(*args, **kwargs)
		self.fields['users'] = forms.ChoiceField(choices = [ (u.id, str(u)) for u in members])

class GroupForm(forms.ModelForm):
	class Meta:
		model = Group
		fields = {'name'}

# class PermissionForm(forms.Form):
#   def __init__(self, ride, *args, **kwargs):
#       super(PermissionForm, self).__init__(*args, **kwargs)
#       self.fields['rides'] = forms.ChoiceField(choices = [ (r.id, str(r)) for r in Ride.objects.filter(start = ride.start, dest = ride.start)])

class DocumentForm(forms.Form):
	docfile = forms.FileField(
		label='Select a file',
		help_text='max. 42 megabytes'
	)
	name = forms.CharField(max_length=200)

class ReportForm(forms.ModelForm):
	def __init__(self, current_user, *args, **kwargs):
		super(ReportForm, self).__init__(*args, **kwargs)
		self.fields['doc'].queryset = Document.objects.filter(author = current_user)
		self.fields['doc'].help_text = ' * &nbsp;&nbsp;' + str(self.fields['doc'].help_text)
		self.fields['keyword'].help_text = ' * &nbsp;&nbsp;' + str(self.fields['keyword'].help_text)
		self.fields['location'].help_text = ' * '
		self.fields['inc_date'].help_text = ' * '
	class Meta:
		model = Report
		fields = ('inc_date', 'author', 'short', 'detailed', 'privacy', 'doc', 'location', 'keyword')
		widgets = {'author':forms.HiddenInput(), 'detailed':forms.Textarea()}

class DeleteReportForm(forms.Form):
	def __init__(self, report_id, *args, **kwargs):
		super(DeleteReportForm, self).__init__(*args, **kwargs)
		self.fields['report'] = forms.IntegerField(initial=report_id, widget=forms.HiddenInput())

class DeleteCommentForm(forms.Form):
	def __init__(self, comments, *args, **kwargs):
		super(DeleteCommentForm, self).__init__(*args, **kwargs)
		self.fields['comment'] = forms.ChoiceField(choices = [ (c.id, str(c) + " - by " + str(c.author)) for c in comments])

class CommentForm(forms.ModelForm):
	class Meta:
		model = Comment
		fields = ('content','report','author')
		widgets = {'author':forms.HiddenInput(),'report':forms.HiddenInput()}

class KeywordForm(forms.ModelForm):
	class Meta:
		model = Keyword
		fields = ('word',)

class SelectReportForm(forms.Form):
	def __init__(self, reports, *args, **kwargs):
		super(SelectReportForm, self).__init__(*args, **kwargs)
		self.fields['report'] = forms.ChoiceField(choices = [ (r.id, str(r)) for r in reports])

class EditForm(forms.ModelForm):
	def __init__(self, current_user, *args, **kwargs):
		super(EditForm, self).__init__(*args, **kwargs)
		self.fields['doc'].queryset = Document.objects.filter(author = current_user)
	class Meta:
		model = Report
		fields = ('author', 'inc_date', 'short', 'detailed', 'privacy', 'doc', 'location', 'groups', 'keyword')
		widgets = {'author':forms.HiddenInput(), 'detailed': forms.Textarea()}

class FolderForm(forms.ModelForm):
	def __init__(self, current_user, *args, **kwargs):
		super(FolderForm, self).__init__(*args, **kwargs)
		self.fields['reports'].queryset = Report.objects.filter(author = current_user)
	class Meta:
		model = Folder
		fields = ('name', 'reports', 'owner')
		widgets = {'owner':forms.HiddenInput()}

class SearchForm(forms.Form):
	query = forms.CharField(max_length=200)
	short = forms.BooleanField()
	detailed = forms.BooleanField()
	location = forms.BooleanField()
	author = forms.BooleanField()
	keyword = forms.BooleanField()
	boolean_terms = forms.ChoiceField(choices = [(True, "Search with AND between terms"), (False, "Search with OR between terms")])
