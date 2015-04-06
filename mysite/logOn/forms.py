from django import forms
from django.core import validators
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

class MyRegistrationForm(UserCreationForm):

    email =forms.EmailField(required=False);

    class Meta:
        model =User
        fields = ('username','email','password1','password2')
        def __init__(self):
            self.fields = (
            forms.TextField(field_name='username',
                            length=30, maxlength=30,
                            is_required=True, validator_list=[validators.isAlphaNumeric,
                                                              self.isValidUsername]),
            forms.EmailField(field_name='email',
                             length=30,
                             maxlength=30,
                             is_required=False),
            forms.PasswordField(field_name='password1',
                                length=30,
                                maxlength=60,
                                is_required=True),
            forms.PasswordField(field_name='password2',
                                length=30, maxlength=60,
                                is_required=True,
                                validator_list=[validators.AlwaysMatchesOtherField('password1',
                                                                                   'Passwords must match.')]),
            )

        def save(self, commit=True):
            user =super(UserCreationForm,self).save(commit=False)
            user.email = self.cleaned_data['email']

            if commit:
                user.save()


                return user

        def isValidUsername(self, field_data, all_data):
         try:
             User.objects.get(username=field_data)
         except User.DoesNotExist:
             return
         raise validators.ValidationError('The username "%s" is already taken.' % field_data)

























