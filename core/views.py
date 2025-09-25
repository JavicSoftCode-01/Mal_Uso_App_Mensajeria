from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Message, SecurityLog, AuthenticationAttempt
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.views.decorators.http import require_http_methods
from django.utils.html import escape
import json
import bleach
import logging
from django.core.cache import cache
from django.conf import settings
from .auth_helpers import check_failed_attempts

def get_client_info(request):
    """Obtiene información detallada del cliente."""
    return {
        'ip': get_client_ip(request),
        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        'session_id': request.session.session_key,
        'request_method': request.method,
        'path': request.path,
    }

def get_client_ip(request):
    """Obtiene la IP real del cliente incluso detrás de proxies."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def log_security_event(request, action, severity='INFO', success=True, details=None):
    """Registra eventos de seguridad de manera centralizada."""
    client_info = get_client_info(request)
    if details is None:
        details = {}
    
    details.update(client_info)
    
    SecurityLog.objects.create(
        user=request.user if request.user.is_authenticated else None,
        action=action,
        ip_address=client_info['ip'],
        severity=severity,
        success=success,
        details=details,
        user_agent=client_info['user_agent'],
        session_id=client_info['session_id']
    )

def check_rate_limit(key, max_attempts, time_window):
    """Implementa limitación de tasa para acciones específicas."""
    current = cache.get(key, 0)
    if current >= max_attempts:
        return False
    cache.set(key, current + 1, time_window)
    return True

@login_required
@require_http_methods(["GET"])
def inbox(request):
    """Vista de bandeja de entrada con medidas de seguridad."""
    rate_limit_key = f'inbox_view_{request.user.id}_{get_client_ip(request)}'
    if not check_rate_limit(rate_limit_key, 30, 60):  # 30 intentos por minuto
        log_security_event(
            request,
            'Rate Limit Exceeded - Inbox View',
            severity='WARN',
            success=False
        )
        messages.error(request, 'Has excedido el límite de accesos. Por favor, espera un momento.')
        return redirect('home')

    messages_received = Message.objects.filter(receiver=request.user)
    log_security_event(request, 'View Inbox')
    
    return render(request, 'core/inbox.html', {
        'messages': messages_received
    })

@login_required
@require_http_methods(["GET", "POST"])
def send_message(request):
    """Vista para enviar mensajes con validaciones de seguridad."""
    logger = logging.getLogger('security')
    
    if request.method == "POST":
        rate_limit_key = f'send_message_{request.user.id}_{get_client_ip(request)}'
        if not check_rate_limit(rate_limit_key, 10, 60):  # 10 mensajes por minuto
            logger.warning(
                'Rate limit exceeded for message sending',
                extra={
                    'ip': get_client_ip(request),
                    'user': request.user.username
                }
            )
            messages.error(
                request,
                'Has excedido el límite de mensajes permitidos por minuto. ' +
                'Por favor, espera un momento antes de intentar nuevamente.'
            )
            return redirect('inbox')

        receiver_username = bleach.clean(request.POST.get('receiver', ''))
        content = bleach.clean(request.POST.get('content', ''))

        if not content or not receiver_username:
            logger.warning(
                'Attempt to send message with missing fields',
                extra={
                    'ip': get_client_ip(request),
                    'user': request.user.username
                }
            )
            messages.error(
                request,
                'Error: Debes completar tanto el destinatario como el contenido del mensaje.'
            )
            return redirect('send_message')
            
        # Validación de auto-mensaje
        if receiver_username.lower() == request.user.username.lower():
            logger.warning(
                'Attempt to send message to self',
                extra={
                    'ip': get_client_ip(request),
                    'user': request.user.username
                }
            )
            messages.error(
                request,
                'Error de seguridad: No está permitido enviarse mensajes a uno mismo. ' +
                'Esta acción ha sido registrada.'
            )
            return redirect('send_message')

        try:
            receiver = User.objects.get(username=receiver_username)
            
            # Validaciones adicionales
            if len(content) > 5000:
                raise ValidationError("El mensaje excede el límite permitido")

            message = Message.objects.create(
                sender=request.user,
                receiver=receiver,
                content=content,
                metadata={
                    'client_info': get_client_info(request),
                    'content_length': len(content),
                    'sent_timestamp': timezone.now().isoformat()
                }
            )

            log_security_event(
                request,
                f'Message Sent',
                details={'receiver': receiver_username, 'message_id': message.id}
            )
            
            messages.success(request, 'Mensaje enviado correctamente.')
            return redirect('inbox')

        except User.DoesNotExist:
            log_security_event(
                request,
                'Invalid Recipient',
                severity='WARN',
                success=False,
                details={'attempted_username': receiver_username}
            )
            messages.error(request, 'Usuario destinatario no existe.')
        
        except ValidationError as e:
            log_security_event(
                request,
                'Message Validation Failed',
                severity='WARN',
                success=False,
                details={'error': str(e)}
            )
            messages.error(request, str(e))
        
        except Exception as e:
            log_security_event(
                request,
                'Message Send Error',
                severity='ERROR',
                success=False,
                details={'error': str(e)}
            )
            messages.error(request, 'Error al enviar el mensaje. Por favor, intenta de nuevo.')
    
    return render(request, 'core/send_message.html')
