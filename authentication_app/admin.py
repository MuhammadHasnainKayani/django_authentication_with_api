from django.contrib import admin
from .models import *

admin.site.register(Article)
admin.site.register(UserProfile)
admin.site.register(UserHistory)
admin.site.register(Favorite)

