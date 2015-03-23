from django.db import models

# Create your models here.
class Report(models.Model):
    author = models.CharField(max_length=30)
    pub_date = models.DateTimeField('date published')
    content = models.CharField(max_length=200)
