# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('content', models.CharField(max_length=200)),
                ('pub_date', models.DateTimeField(default=datetime.datetime.today)),
                ('author', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Document',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=200)),
                ('docfile', models.FileField(upload_to='documents/%Y/%m/%d')),
                ('encrypted', models.BooleanField(default=False)),
                ('sign', models.BooleanField(default=False)),
                ('author', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Folder',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(default='name', max_length=200)),
                ('pub_date', models.DateTimeField(default=datetime.datetime.today)),
                ('owner', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Keyword',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('word', models.CharField(max_length=200)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('pub_date', models.DateTimeField(default=datetime.datetime.today)),
                ('inc_date', models.DateTimeField(null=True, blank=True)),
                ('short', models.CharField(default='default short', max_length=200)),
                ('detailed', models.CharField(default='default detail', max_length=2000)),
                ('privacy', models.BooleanField(default=True)),
                ('location', models.CharField(blank=True, default='default location', max_length=200)),
                ('author', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
                ('doc', models.ManyToManyField(null=True, blank=True, to='SecureWitness.Document')),
                ('groups', models.ManyToManyField(null=True, blank=True, to='auth.Group')),
                ('keyword', models.ManyToManyField(null=True, blank=True, to='SecureWitness.Keyword')),
            ],
            options={
                'permissions': (('can_read', 'Permission to read file'), ('can_search', 'Permission to search for file')),
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('activation_key', models.CharField(blank=True, max_length=40)),
                ('key_expires', models.DateTimeField(default=datetime.date(2015, 4, 26))),
                ('user', models.OneToOneField(to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name_plural': 'User profiles',
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='folder',
            name='reports',
            field=models.ManyToManyField(null=True, blank=True, to='SecureWitness.Report'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='comment',
            name='report',
            field=models.ForeignKey(to='SecureWitness.Report'),
            preserve_default=True,
        ),
    ]
