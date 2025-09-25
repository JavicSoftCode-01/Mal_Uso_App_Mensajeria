from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import logging
from .models import AuthenticationAttempt
from .views import get_client_ip

logger = logging.getLogger('auth')

def check_failed_attempts(username, ip_address):
    """
    Verifica los intentos fallidos de login y envía email si es necesario.
    Retorna True si se debe permitir otro intento, False si se debe bloquear.
    """
    # Buscar intentos fallidos en los últimos 10 minutos
    time_threshold = timezone.now() - timedelta(minutes=10)
    recent_attempts = AuthenticationAttempt.objects.filter(
        username=username,
        ip_address=ip_address,
        timestamp__gte=time_threshold,
        success=False
    )

    attempt_count = recent_attempts.count()
    
    # Si hay 2 o más intentos fallidos, enviar email
    if attempt_count >= 2:
        subject = 'Alerta de Seguridad - Intentos de inicio de sesión fallidos'
        message = f'''Se han detectado múltiples intentos de inicio de sesión fallidos:
        Usuario: {username}
        IP: {ip_address}
        Número de intentos: {attempt_count}
        Último intento: {timezone.now()}
        
        Si no reconoces estos intentos, por favor contacta al administrador.
        '''
        try:
            admin_email = getattr(settings, 'ADMIN_EMAIL', 'admin@example.com')
            send_mail(
                subject,
                message,
                settings.EMAIL_HOST_USER,
                [admin_email],
                fail_silently=False,
            )
            logger.warning(
                f'Email de alerta enviado por múltiples intentos fallidos',
                extra={'user': username, 'ip': ip_address}
            )
        except Exception as e:
            logger.error(
                f'Error al enviar email de alerta: {str(e)}',
                extra={'user': username, 'ip': ip_address}
            )
    
    # Bloquear después de 5 intentos fallidos
    return attempt_count < 5

@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        ip_address = get_client_ip(request)
        
        if not check_failed_attempts(username, ip_address):
            logger.warning(
                'Cuenta bloqueada por múltiples intentos fallidos',
                extra={'user': username, 'ip': ip_address}
            )
            messages.error(
                request,
                'Cuenta temporalmente bloqueada por múltiples intentos fallidos. '
                'Por favor, intenta más tarde.'
            )
            return redirect('login')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            # Registrar intento exitoso
            AuthenticationAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=True
            )
            logger.info(
                'Inicio de sesión exitoso',
                extra={'user': username, 'ip': ip_address}
            )
            return redirect('inbox')
        else:
            # Registrar intento fallido
            AuthenticationAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False
            )
            logger.warning(
                'Intento de inicio de sesión fallido',
                extra={'user': username, 'ip': ip_address}
            )
            messages.error(request, 'Usuario o contraseña incorrectos.')
    
    return render(request, 'core/login.html')

@require_http_methods(["GET"])
def logout_view(request):
    if request.user.is_authenticated:
        username = request.user.username
        ip_address = get_client_ip(request)
        logout(request)
        logger.info(
            'Cierre de sesión exitoso',
            extra={'user': username, 'ip': ip_address}
        )
    return redirect('login')