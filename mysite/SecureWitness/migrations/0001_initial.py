# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings
import datetime


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Document',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('docfile', models.FileField(upload_to='documents/%Y/%m/%d')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('pub_date', models.DateTimeField(default=datetime.datetime.today)),
                ('inc_date', models.DateTimeField(blank=True, null=True)),
                ('short', models.CharField(max_length=200)),
                ('detailed', models.CharField(max_length=2000)),
                ('privacy', models.BooleanField(default=True)),
                ('location', models.CharField(blank=True, max_length=200)),
                ('author', models.OneToOneField(to=settings.AUTH_USER_MODEL)),
                ('doc', models.ManyToManyField(blank=True, to='SecureWitness.Document', null=True)),
            ],
            options={
                'permissions': (('can_read', 'Permission to read file'),),
            },
            bases=(models.Model,),
        ),
    ]
