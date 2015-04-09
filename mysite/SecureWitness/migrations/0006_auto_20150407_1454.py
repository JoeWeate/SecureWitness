# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('SecureWitness', '0005_auto_20150405_2340'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='report',
            options={'permissions': (('can_read', 'Permission to read file'),)},
        ),
        migrations.AddField(
            model_name='report',
            name='privacy',
            field=models.BooleanField(default=True),
            preserve_default=True,
        ),
    ]
