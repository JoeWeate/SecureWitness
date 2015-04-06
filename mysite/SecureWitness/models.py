from django.db import models
from django.utils import timezone

# Create your models here.
class Folder(models.Model):
	author = models.CharField(max_length=30)
	name = models.CharField(max_length=30)
	create_date = models.DateTimeField('date published')

class Report(models.Model):
    author = models.CharField(max_length=30)
    pub_date = models.DateTimeField('date published')
    content = models.CharField(max_length=200)

