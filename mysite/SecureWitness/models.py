from django.db import models
from django.contrib.auth.models import User, Group
import datetime

# Create your models here.
class Document(models.Model):
	docfile = models.FileField(upload_to='documents/%Y/%m/%d')
	#encfile = models.FileField(blank=True, upload_to='documents/%Y/%m/%d')
	encrypted = models.BooleanField(default=False)


class Keyword(models.Model):
	word = models.CharField(max_length=200)

class Report(models.Model):
	# User who created report
	author = models.ForeignKey(User)
	# Date of publication
	pub_date = models.DateTimeField(default=datetime.datetime.today)
	# Date and time of incident
	inc_date = models.DateTimeField(null=True, blank=True)
	# Short description (1 line)
	short = models.CharField(max_length=200)
	# Detailed description
	detailed = models.CharField(max_length=2000)
	# Privacy setting (default private)
	privacy = models.BooleanField(default=True)
	# Optional document field for uploading one or more documents
	doc = models.ManyToManyField(Document,null=True,blank=True)
	# Optional location char field
	location = models.CharField(max_length=200,blank=True)
	# Optional keywords associated with report
	keyword = models.ManyToManyField(Keyword,null=True,blank=True)
	# Optional group associated with report,
	# allowing them to search and access otherwise private reports
	groups = models.ManyToManyField(Group, null=True, blank=True)

	def __str__(self):
		return self.short

	class Meta:
		permissions = (
			("can_read", "Permission to read file"),
			("can_search", "Permission to search for file"),
		)
	
	

class Folder(models.Model):
	reports = models.ManyToManyField(Report,null=True,blank=True)
	name = models.CharField(max_length=200)
	owner = models.ForeignKey(User)
	pub_date = models.DateTimeField(default=datetime.datetime.today)
	def __str__(self):
		return self.name
