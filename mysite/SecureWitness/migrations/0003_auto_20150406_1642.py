# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('SecureWitness', '0002_auto_20150406_1630'),
    ]

    operations = [
        migrations.CreateModel(
            name='Folder',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False, auto_created=True, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('pub_date', models.DateTimeField(default=datetime.datetime.today)),
                ('owner', models.OneToOneField(to=settings.AUTH_USER_MODEL)),
                ('reports', models.ManyToManyField(to='SecureWitness.Report', blank=True, null=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.RemoveField(
            model_name='superuser',
            name='user',
        ),
        migrations.DeleteModel(
            name='Superuser',
        ),
        migrations.AlterModelOptions(
            name='report',
            options={'permissions': (('can_read', 'Permission to read file'), ('can_search', 'Permission to search for file'))},
        ),
    ]
