from django.contrib.auth.models import User
from django.db import models
from tinymce.models import HTMLField

# Article model for storing content
class Article(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE)  # Admin user link
    title = models.CharField(max_length=255)
    language = models.CharField(max_length=50)
    content = HTMLField()  # TinyMCE rich text field
    views = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.title

# UserHistory model for tracking viewed articles
class UserHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    article = models.ForeignKey(Article, on_delete=models.CASCADE)
    viewed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} viewed {self.article.title} on {self.viewed_at}"

# Favorite model for storing user-favorited articles
class Favorite(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    article = models.ForeignKey(Article, on_delete=models.CASCADE)
    favorited_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} favorited {self.article.title} on {self.favorited_at}"

class UserProfile(models.Model):
    USER_TYPE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User')
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    favorites_count = models.IntegerField(default=0)
    user_type = models.CharField(max_length=5, choices=USER_TYPE_CHOICES, default='user')

    def __str__(self):
        return f"{self.user_type.capitalize()}: {self.user.email}"

