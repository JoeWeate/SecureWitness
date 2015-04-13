# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('SecureWitness', '0003_document_encfile'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='document',
            name='encfile',
        ),
    ]
