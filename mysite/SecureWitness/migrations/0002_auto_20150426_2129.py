# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('SecureWitness', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='report',
            name='detailed',
            field=models.CharField(max_length=2000),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='report',
            name='location',
            field=models.CharField(max_length=200, blank=True, null=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='report',
            name='short',
            field=models.CharField(max_length=200),
            preserve_default=True,
        ),
    ]
