# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.utils.timezone import utc
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('SecureWitness', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='report',
            name='author',
            field=models.CharField(default=datetime.datetime(2015, 3, 23, 20, 16, 33, 663591, tzinfo=utc), max_length=30),
            preserve_default=False,
        ),
    ]
