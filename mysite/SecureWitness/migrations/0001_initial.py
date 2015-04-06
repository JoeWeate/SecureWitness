# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Document',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('docfile', models.FileField(upload_to='documents/%Y/%m/%d')),
                ('encrypted', models.BooleanField(default=False)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Folder',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('name', models.CharField(max_length=200)),
                ('pub_date', models.DateTimeField(default=datetime.datetime.today)),
                ('owner', models.OneToOneField(to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Keyword',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('word', models.CharField(max_length=200)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, primary_key=True, auto_created=True)),
                ('pub_date', models.DateTimeField(default=datetime.datetime.today)),
                ('inc_date', models.DateTimeField(blank=True, null=True)),
                ('short', models.CharField(max_length=200)),
                ('detailed', models.CharField(max_length=2000)),
                ('privacy', models.BooleanField(default=True)),
                ('location', models.CharField(blank=True, max_length=200)),
                ('author', models.OneToOneField(to=settings.AUTH_USER_MODEL)),
                ('doc', models.ManyToManyField(to='SecureWitness.Document', blank=True, null=True)),
                ('keyword', models.ManyToManyField(to='SecureWitness.Keyword', blank=True, null=True)),
            ],
            options={
                'permissions': (('can_read', 'Permission to read file'), ('can_search', 'Permission to search for file')),
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='folder',
            name='reports',
            field=models.ManyToManyField(to='SecureWitness.Report', blank=True, null=True),
            preserve_default=True,
        ),
    ]
