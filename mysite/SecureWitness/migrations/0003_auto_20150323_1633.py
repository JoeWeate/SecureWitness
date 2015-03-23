# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('SecureWitness', '0002_report_author'),
    ]

    operations = [
        migrations.RenameField(
            model_name='report',
            old_name='put_date',
            new_name='pub_date',
        ),
    ]
