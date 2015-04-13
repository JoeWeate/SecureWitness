# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('SecureWitness', '0002_auto_20150410_0057'),
    ]

    operations = [
        migrations.AddField(
            model_name='document',
            name='encfile',
            field=models.FileField(upload_to='documents/%Y/%m/%d', blank=True),
            preserve_default=True,
        ),
    ]
