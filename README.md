# Práctica de Seguridad de Software - App de Mensajería

## 1. REQUISITOS DE SEGURIDAD

### 1.1 Importancia de la Seguridad desde Etapas Iniciales

Razones para definir requisitos de seguridad en fases tempranas:
1. Reducción de costos: Identificar y corregir problemas de seguridad en etapas tempranas es significativamente más económico.
2. Diseño más robusto: Permite diseñar la arquitectura considerando la seguridad como parte integral.
3. Mejor gestión de riesgos: Facilita la identificación y mitigación de riesgos antes de que se conviertan en vulnerabilidades.

Consecuencias de no considerar la seguridad temprano:
- Costos elevados de corrección
- Vulnerabilidades estructurales difíciles de corregir
- Posible necesidad de rediseño completo
- Mayor riesgo de brechas de seguridad

### 1.2 Caso de Mal Uso - Aplicación de Mensajería

#### Caso de Mal Uso:
**Escenario**: Suplantación de identidad en mensajería
- Actor malicioso intercepta sesión de usuario
- Accede a historial de mensajes
- Envía mensajes fraudulentos a contactos

#### Contramedidas Implementadas:
1. Autenticación de dos factores
2. Encriptación de mensajes
3. Sistema de logs de seguridad
4. Detección de comportamiento anómalo
5. Sesiones con tiempo limitado

### 1.3 Técnicas de Recolección de Requisitos

Técnicas aplicadas:
1. Entrevistas con stakeholders
2. Análisis de amenazas (STRIDE)

Ejemplo de requisito obtenido:
"El sistema debe implementar cifrado end-to-end para todos los mensajes intercambiados entre usuarios."

### 1.4 Priorización de Requisitos de Seguridad

Lista de requisitos priorizados (usando matriz impacto/probabilidad):

1. [CRÍTICO] Implementación de autenticación segura
2. [ALTO] Cifrado de mensajes en tránsito
3. [ALTO] Sistema de logging de seguridad
4. [MEDIO] Control de sesiones
5. [MEDIO] Validación de entrada de datos

## 2. ESTÁNDARES DE SEGURIDAD

### 2.1 ISO/IEC 27000

Definición:
Framework que proporciona un sistema de gestión de seguridad de la información (SGSI), estableciendo estándares para proteger activos de información.

Beneficios:
1. Marco estructurado para gestionar la seguridad
2. Mejora continua en prácticas de seguridad

### 2.2 ISO/IEC 27001:2013

Controles implementados:
1. Control de acceso
2. Criptografía
3. Seguridad operacional

Prevención de riesgos:
- Control de acceso: Previene accesos no autorizados
- Criptografía: Protege la confidencialidad de datos
- Seguridad operacional: Asegura la integridad del sistema

### 2.3 ISO/IEC 27002:2013

Área de control seleccionada: Control de Acceso
- Política de control de acceso
- Gestión de acceso de usuarios
- Control de acceso a sistemas y aplicaciones

### 2.4 OWASP

Riesgo seleccionado: Broken Authentication
Ejemplo: Ataque de fuerza bruta en login
Mitigación: 
- Implementación de captcha
- Bloqueo temporal después de intentos fallidos
- Políticas de contraseñas fuertes

## 3. INGENIERÍA DE REQUISITOS

### 3.1 Clasificación de Requisitos

#### Requisitos Funcionales:
1. "El sistema debe permitir enviar mensajes entre usuarios"
2. "Los usuarios deben poder ver su historial de mensajes"

#### Requisitos No Funcionales:
1. "El sistema debe responder en menos de 2 segundos"
2. "La interfaz debe ser accesible en dispositivos móviles"

#### Requisitos de Seguridad:
1. "Todos los mensajes deben estar cifrados end-to-end"
2. "Las sesiones deben expirar después de 30 minutos de inactividad"

### 3.2 IREB (International Requirements Engineering Board)

Principios clave:
1. Trazabilidad de requisitos
2. Verificabilidad
3. Coherencia
4. No ambigüedad

## 4. REVISIÓN DE CÓDIGO SEGURO

### 4.1 Formas de Revisión Segura
1. Análisis estático automatizado
2. Revisión manual por pares
3. Pruebas de penetración

Consecuencias de no revisar:
- Vulnerabilidades no detectadas
- Problemas de seguridad en producción
- Costos elevados de corrección

### 4.2 Code Smells Identificados
1. Almacenamiento de contraseñas en texto plano
2. Falta de validación de entrada

### 4.3 Revisión según OWASP

Checklist aplicada:
- Validación de entrada
- Gestión de sesiones
- Control de acceso
- Manejo de errores

## Guía de Instalación y Uso

### Requisitos Previos
- Python 3.8 o superior
- pip (gestor de paquetes de Python)
- Git

### Pasos de Instalación

1. Clonar el repositorio:
```bash
git clone [URL_del_repositorio]
cd Mal_Uso_App_Mensajeria
```

2. Crear y activar entorno virtual:
```bash
python -m venv venv
# En Windows:
.\venv\Scripts\activate
# En Linux/Mac:
source venv/bin/activate
```

3. Instalar dependencias:
```bash
pip install -r requirements.txt
```

4. Configurar la base de datos:
```bash
python manage.py migrate
```

5. Crear superusuario:
```bash
python manage.py createsuperuser
```

6. Iniciar el servidor:
```bash
python manage.py runserver
```

### Uso del Sistema

1. Acceder a la aplicación:
   - Abrir navegador y visitar: http://localhost:8000

2. Iniciar sesión:
   - Usar credenciales de superusuario o crear nueva cuenta

3. Funcionalidades principales:
   - Enviar mensajes
   - Ver bandeja de entrada
   - Gestionar perfil

### Consideraciones de Seguridad

1. En desarrollo:
   - No usar en producción sin modificar SECRET_KEY
   - Mantener DEBUG = True solo en desarrollo

2. En producción:
   - Configurar ALLOWED_HOSTS
   - Activar HTTPS
   - Configurar políticas de seguridad
   - Implementar backups regulares

### Sistema de Logging Implementado

Se ha implementado un sistema de logging robusto con las siguientes características:

#### Tipos de Logs
1. **Security Log** (`security.log`):
   - Eventos de seguridad críticos
   - Intentos de acceso no autorizados
   - Cambios en permisos

2. **Authentication Log** (`auth.log`):
   - Intentos de inicio de sesión
   - Bloqueos de cuenta
   - Cambios de contraseña

3. **Django Log** (`django.log`):
   - Logs generales del framework
   - Peticiones HTTP
   - Errores de aplicación

4. **Error Log** (`error.log`):
   - Errores críticos
   - Excepciones no manejadas
   - Problemas de configuración

#### Configuración de Logging

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{levelname}] {asctime} {name} - {message}',
            'style': '{',
        },
        'simple': {
            'format': '[{levelname}] {message}',
            'style': '{',
        },
    },
    'handlers': {
        'security_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'logs/security.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django.security': {
            'handlers': ['security_file', 'mail_admins'],
            'level': 'INFO',
            'propagate': False,
        },
    }
}
```

### Mejoras de Seguridad Implementadas

1. **Sistema de Notificaciones**:
   - Alertas por email para intentos de acceso sospechosos
   - Notificaciones de actividades inusuales
   - Reportes de seguridad automáticos

2. **Control de Acceso Mejorado**:
   - Bloqueo de cuenta después de intentos fallidos
   - Validación de sesiones activas
   - Control de acceso basado en roles

3. **Monitoreo y Auditoría**:
   - Registro detallado de todas las actividades
   - Sistema de logs centralizado
   - Alertas en tiempo real
