from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.models import User
import logging
from .models import AuthenticationAttempt
from django.utils import timezone

auth_logger = logging.getLogger('auth')
security_logger = logging.getLogger('security')

def send_security_alert(username, ip_address):
    """Envía alerta de seguridad por correo electrónico."""
    try:
        user = User.objects.get(username=username)
        subject = 'Alerta de Seguridad - Intentos de acceso fallidos'
        message = f'''
        Se han detectado múltiples intentos fallidos de acceso a tu cuenta.
        
        Detalles:
        - Usuario: {username}
        - Dirección IP: {ip_address}
        - Fecha y hora: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Si no has sido tú, te recomendamos cambiar tu contraseña inmediatamente.
        '''
        
        send_mail(
            subject,
            message,
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )
        
        security_logger.info(
            'Security alert email sent',
            extra={
                'ip': ip_address,
                'user': username
            }
        )
    except Exception as e:
        security_logger.error(
            f'Failed to send security alert email: {str(e)}',
            extra={
                'ip': ip_address,
                'user': username
            }
        )

def check_failed_attempts(username, ip_address):
    """Verifica intentos fallidos de login y envía alertas si es necesario."""
    try:
        attempts = AuthenticationAttempt.objects.filter(
            username=username,
            ip_address=ip_address,
            timestamp__gte=timezone.now() - timezone.timedelta(minutes=30)
        ).count()
        
        if attempts >= 2:  # Después de 2 intentos fallidos
            send_security_alert(username, ip_address)
            return True
            
    except Exception as e:
        security_logger.error(
            f'Error checking failed attempts: {str(e)}',
            extra={
                'ip': ip_address,
                'user': username
            }
        )
    
    return False