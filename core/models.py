from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.conf import settings
import json

class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    is_read = models.BooleanField(default=False)
    is_encrypted = models.BooleanField(default=True)
    signature = models.TextField(null=True, blank=True)
    metadata = models.JSONField(default=dict)

    class Meta:
        ordering = ['-timestamp']

    def clean(self):
        if self.sender == self.receiver:
            raise ValidationError("No puede enviarse mensajes a sí mismo")
        if len(self.content) > 5000:
            raise ValidationError("El mensaje excede el límite de caracteres permitido")

    def save(self, *args, **kwargs):
        if not self.metadata:
            self.metadata = {
                'client_info': {},
                'sent_timestamp': timezone.now().isoformat(),
                'message_type': 'standard'
            }
        super().save(*args, **kwargs)

    def __str__(self):
        return f'Message from {self.sender} to {self.receiver}'

class SecurityLog(models.Model):
    SEVERITY_CHOICES = [
        ('INFO', 'Information'),
        ('WARN', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField()
    success = models.BooleanField(default=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='INFO')
    details = models.JSONField(default=dict)
    user_agent = models.TextField(null=True, blank=True)
    session_id = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'severity']),
            models.Index(fields=['user', 'action']),
        ]

    def save(self, *args, **kwargs):
        if not self.details:
            self.details = {
                'timestamp': timezone.now().isoformat(),
                'environment': 'production' if not settings.DEBUG else 'development'
            }
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.user} - {self.action} - {self.severity} - {self.timestamp}'

class AuthenticationAttempt(models.Model):
    username = models.CharField(max_length=150)
    timestamp = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField()
    success = models.BooleanField(default=False)
    attempt_count = models.IntegerField(default=1)
    blocked_until = models.DateTimeField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['username', 'ip_address']),
        ]

    def increment_attempts(self):
        self.attempt_count += 1
        if self.attempt_count >= 5:
            self.blocked_until = timezone.now() + timezone.timedelta(minutes=30)
        self.save()
