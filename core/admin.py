from django.contrib import admin
from .models import Message, SecurityLog

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'timestamp', 'is_read')
    list_filter = ('is_read', 'timestamp')
    search_fields = ('sender__username', 'receiver__username', 'content')
    date_hierarchy = 'timestamp'

@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'timestamp', 'ip_address', 'success')
    list_filter = ('success', 'timestamp')
    search_fields = ('user__username', 'action', 'ip_address')
    date_hierarchy = 'timestamp'
