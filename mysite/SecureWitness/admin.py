from django.contrib import admin
from SecureWitness.models import Report, Folder, Keyword, Document,UserProfile, Comment
# Register your models here.
admin.site.register(Report)
admin.site.register(Folder)
admin.site.register(Keyword)
admin.site.register(Document)
admin.site.register(UserProfile)
admin.site.register(Comment)