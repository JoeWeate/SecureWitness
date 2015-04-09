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
                ('id', models.AutoField(auto_created=True, verbose_name='ID', primary_key=True, serialize=False)),
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
                ('id', models.AutoField(auto_created=True, verbose_name='ID', primary_key=True, serialize=False)),
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
                ('id', models.AutoField(auto_created=True, verbose_name='ID', primary_key=True, serialize=False)),
                ('word', models.CharField(max_length=200)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.AutoField(auto_created=True, verbose_name='ID', primary_key=True, serialize=False)),
                ('pub_date', models.DateTimeField(default=datetime.datetime.today)),
                ('inc_date', models.DateTimeField(blank=True, null=True)),
                ('short', models.CharField(max_length=200)),
                ('detailed', models.CharField(max_length=2000)),
                ('privacy', models.BooleanField(default=True)),
                ('location', models.CharField(blank=True, max_length=200)),
                ('author', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
                ('doc', models.ManyToManyField(blank=True, to='SecureWitness.Document', null=True)),
                ('keyword', models.ManyToManyField(blank=True, to='SecureWitness.Keyword', null=True)),
            ],
            options={
                'permissions': (('can_read', 'Permission to read file'), ('can_search', 'Permission to search for file')),
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='folder',
            name='reports',
            field=models.ManyToManyField(blank=True, to='SecureWitness.Report', null=True),
            preserve_default=True,
        ),
    ]
