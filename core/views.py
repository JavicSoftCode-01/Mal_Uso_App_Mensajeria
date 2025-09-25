from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Message, SecurityLog, AuthenticationAttempt
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.views.decorators.http import require_http_methods
from django.utils.html import escape
from django.db.models import Q
import json
import bleach
import logging
from django.core.cache import cache
from django.conf import settings
from .auth_helpers import check_failed_attempts

def get_chat_history(user1, user2):
    """Obtiene el historial de chat entre dos usuarios."""
    return Message.objects.filter(
        (Q(sender=user1, receiver=user2) | Q(sender=user2, receiver=user1))
    ).order_by('timestamp')

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
        return redirect('inbox')

    # Obtener chats únicos agrupados por usuario
    chats = Message.objects.filter(
        Q(sender=request.user) | Q(receiver=request.user)
    ).order_by('-timestamp')
    
    # Crear una lista de chats únicos con el último mensaje
    unique_chats = {}
    for chat in chats:
        other_user = chat.receiver if chat.sender == request.user else chat.sender
        if other_user.id not in unique_chats:
            unique_chats[other_user.id] = {
                'user': other_user,
                'last_message': chat,
                'unread_count': Message.objects.filter(
                    sender=other_user,
                    receiver=request.user,
                    is_read=False
                ).count()
            }
    
    log_security_event(request, 'View Inbox')
    
    return render(request, 'core/inbox.html', {
        'chats': sorted(unique_chats.values(), key=lambda x: x['last_message'].timestamp, reverse=True)
    })

@login_required
@require_http_methods(["GET", "POST"])
def chat_view(request, user_id):
    """Vista de chat individual."""
    other_user = get_object_or_404(User, id=user_id)
    logger = logging.getLogger('security')
    
    if request.method == "POST":
        content = bleach.clean(request.POST.get('content', ''))
        
        if not content:
            messages.error(request, 'El mensaje no puede estar vacío.')
            return redirect('chat', user_id=user_id)
        
        try:
            Message.objects.create(
                sender=request.user,
                receiver=other_user,
                content=content,
                is_read=False
            )
            logger.info(
                'Message sent in chat',
                extra={
                    'sender': request.user.username,
                    'receiver': other_user.username,
                    'ip': get_client_ip(request)
                }
            )
            
        except ValidationError as e:
            messages.error(request, str(e))
            logger.warning(
                'Message validation failed',
                extra={
                    'error': str(e),
                    'sender': request.user.username,
                    'receiver': other_user.username
                }
            )
            
    # Marcar mensajes como leídos
    Message.objects.filter(
        sender=other_user,
        receiver=request.user,
        is_read=False
    ).update(is_read=True)
    
    # Obtener historial de chat
    chat_history = get_chat_history(request.user, other_user)
    
    return render(request, 'core/chat.html', {
        'other_user': other_user,
        'chat_history': chat_history,
    })

@login_required
@require_http_methods(["GET", "POST"])
def send_message(request):
    """Vista para iniciar un nuevo chat o responder a uno existente."""
    logger = logging.getLogger('security')
    context = {}
    
    # Verificar si es una respuesta a un mensaje existente
    reply_to = request.GET.get('reply_to')
    if reply_to:
        try:
            receiver = User.objects.get(username=reply_to)
            context['receiver'] = receiver
            context['chat_history'] = get_chat_history(request.user, receiver)
        except User.DoesNotExist:
            messages.error(request, 'El usuario especificado no existe.')
    
    if request.method == "POST":
        rate_limit_key = f'send_message_{request.user.id}_{get_client_ip(request)}'
        if not check_rate_limit(rate_limit_key, 10, 60):
            logger.warning(
                'Rate limit exceeded for message sending',
                extra={
                    'ip': get_client_ip(request),
                    'user': request.user.username
                }
            )
            messages.error(request, 'Has excedido el límite de mensajes. Por favor, espera un momento.')
            return redirect('inbox')

        receiver_username = bleach.clean(request.POST.get('receiver', ''))
        content = bleach.clean(request.POST.get('content', ''))

        if not content or not receiver_username:
            logger.warning(
                'Campos incompletos en envío de mensaje',
                extra={
                    'extra': json.dumps({
                        'user': request.user.username,
                        'ip': get_client_ip(request)
                    })
                }
            )
            messages.error(request, 'Todos los campos son requeridos.')
            return redirect('send_message')
            
        if receiver_username.lower() == request.user.username.lower():
            logger.warning(
                'Intento de auto-mensaje detectado',
                extra={
                    'extra': json.dumps({
                        'user': request.user.username,
                        'ip': get_client_ip(request)
                    })
                }
            )
            messages.error(request, 'No puedes enviarte mensajes a ti mismo.')
            return redirect('send_message')

        try:
            receiver = User.objects.get(username=receiver_username)
            
            if len(content) > 5000:
                raise ValidationError("El mensaje excede el límite permitido")

            message = Message.objects.create(
                sender=request.user,
                receiver=receiver,
                content=content,
                is_read=False
            )

            logger.info(
                'Mensaje enviado correctamente',
                extra={
                    'extra': json.dumps({
                        'sender': request.user.username,
                        'receiver': receiver_username,
                        'message_id': message.id
                    })
                }
            )
            return redirect('chat', user_id=receiver.id)

        except User.DoesNotExist:
            logger.warning('Invalid recipient',
                         extra={'attempted_username': receiver_username})
            messages.error(request, 'El usuario destinatario no existe.')
        
        except ValidationError as e:
            logger.warning('Message validation failed',
                         extra={'error': str(e)})
            messages.error(request, str(e))
        
        except Exception as e:
            logger.error('Unexpected error sending message',
                        extra={'error': str(e)})
            messages.error(request, 'Error al enviar el mensaje. Por favor, intenta de nuevo.')
    
    return render(request, 'core/send_message.html', context)
