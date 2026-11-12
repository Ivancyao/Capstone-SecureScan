"""
Traducción al español de las alertas más comunes de OWASP ZAP.

ZAP entrega nombre, descripción y solución en inglés. Para las alertas que este catálogo conoce se muestran
en español; las demás se muestran con el texto original y una nota que lo indica. Se busca por el nombre
de la alerta (estable entre versiones de ZAP), sin distinguir mayúsculas.
Cada entrada: nombre en español, descripción, recomendación.
"""
import re
from typing import Dict, Optional, Tuple

Entrada = Tuple[str, str, str]

_PROTEGER_CACHE = "Configurar Cache-Control con no-store, no-cache, must-revalidate y private para el contenido sensible."

CATALOGO: Dict[str, Entrada] = {
    "content security policy (csp) header not set": (
        "Falta la cabecera Content-Security-Policy (CSP)",
        "La Política de Seguridad de Contenido (CSP) es una capa adicional de seguridad que ayuda a detectar y mitigar ciertos ataques, como Cross-Site Scripting (XSS) e inyección de datos, que se usan desde el robo de información hasta la alteración del sitio o la distribución de malware.",
        "Configurar el servidor web, el servidor de aplicaciones o el balanceador de carga para enviar la cabecera Content-Security-Policy con una política restrictiva.",
    ),
    "cross-domain misconfiguration": (
        "Configuración incorrecta entre dominios (CORS)",
        "El navegador puede cargar datos desde otros dominios por una configuración incorrecta de Cross-Origin Resource Sharing (CORS) en el servidor, por ejemplo Access-Control-Allow-Origin con el valor comodín *.",
        "Evitar el comodín en Access-Control-Allow-Origin y permitir solo los orígenes de confianza que realmente lo necesiten. No exponer datos sensibles sin autenticación.",
    ),
    "modern web application": (
        "Aplicación web moderna (SPA)",
        "La aplicación parece ser una aplicación web moderna que carga su contenido dinámicamente con JavaScript. Es un hallazgo informativo: el spider estándar de ZAP puede explorarla de forma incompleta.",
        "Sin acción de seguridad. Para análisis más completos, usar el AJAX Spider o el Client Spider de ZAP.",
    ),
    "missing anti-clickjacking header": (
        "Falta protección contra clickjacking",
        "La respuesta no incluye la directiva frame-ancestors de Content-Security-Policy ni la cabecera X-Frame-Options, por lo que la página podría incrustarse en un marco de otro sitio y usarse en ataques de clickjacking.",
        "Enviar Content-Security-Policy con frame-ancestors (preferido) o X-Frame-Options con DENY o SAMEORIGIN.",
    ),
    "x-content-type-options header missing": (
        "Falta la cabecera X-Content-Type-Options",
        "No se envía X-Content-Type-Options: nosniff, lo que permite que algunos navegadores interpreten el contenido con un tipo distinto al declarado (MIME sniffing).",
        "Enviar X-Content-Type-Options: nosniff en todas las respuestas y declarar correctamente el Content-Type.",
    ),
    "strict-transport-security header not set": (
        "Falta la cabecera Strict-Transport-Security (HSTS)",
        "HTTP Strict Transport Security (HSTS) obliga al navegador a usar siempre HTTPS con el sitio. Sin ella, es más fácil degradar la conexión y realizar ataques de intermediario.",
        "Enviar Strict-Transport-Security con un max-age adecuado (por ejemplo, un año) en todas las respuestas HTTPS.",
    ),
    'server leaks version information via "server" http response header field': (
        "El servidor revela su versión en la cabecera Server",
        "La cabecera Server entrega información de versión del software, lo que facilita a un atacante buscar vulnerabilidades conocidas.",
        "Configurar el servidor para no revelar la versión o suprimir la cabecera Server.",
    ),
    'server leaks information via "x-powered-by" http response header field(s)': (
        "El servidor revela tecnologías en la cabecera X-Powered-By",
        "La cabecera X-Powered-By indica con qué tecnologías funciona la aplicación, información útil para planear ataques dirigidos.",
        "Eliminar la cabecera X-Powered-By de las respuestas.",
    ),
    "cookie no httponly flag": (
        "Cookie sin la marca HttpOnly",
        "Una cookie sin HttpOnly puede ser leída por scripts del navegador. Si existe una falla XSS, un atacante podría robar la sesión.",
        "Marcar las cookies de sesión con HttpOnly.",
    ),
    "cookie without secure flag": (
        "Cookie sin la marca Secure",
        "Una cookie sin Secure puede enviarse por conexiones HTTP sin cifrar, donde podría ser interceptada.",
        "Marcar las cookies con Secure y servir el sitio solo por HTTPS.",
    ),
    "cookie without samesite attribute": (
        "Cookie sin el atributo SameSite",
        "Sin SameSite, el navegador puede enviar la cookie en solicitudes iniciadas desde otros sitios, lo que facilita ataques CSRF.",
        "Establecer SameSite=Lax o SameSite=Strict en las cookies.",
    ),
    "loosely scoped cookie": (
        "Cookie con alcance demasiado amplio",
        "El dominio o la ruta de la cookie es demasiado permisivo, por lo que podría enviarse a subdominios que no son de confianza.",
        "Restringir los atributos Domain y Path de la cookie al mínimo necesario.",
    ),
    "re-examine cache-control directives": (
        "Revisar las directivas Cache-Control",
        "La cabecera Cache-Control falta o es insegura, por lo que contenido sensible podría quedar guardado en cachés compartidas.",
        _PROTEGER_CACHE,
    ),
    "storable and cacheable content": (
        "Contenido almacenable y cacheable",
        "La respuesta puede ser almacenada y reutilizada por cachés compartidas. Si contiene datos sensibles, podrían exponerse a otros usuarios.",
        _PROTEGER_CACHE,
    ),
    "storable but non-cacheable content": (
        "Contenido almacenable pero no cacheable",
        "La respuesta puede almacenarse, pero no reutilizarse sin validación. Es un hallazgo informativo.",
        "Sin acción necesaria, salvo que el contenido sea sensible: en ese caso usar Cache-Control: no-store.",
    ),
    "non-storable content": (
        "Contenido no almacenable",
        "La respuesta indica que no puede guardarse en caché. Es un hallazgo informativo.",
        "Sin acción necesaria.",
    ),
    "retrieved from cache": (
        "Respuesta recuperada desde caché",
        "La respuesta fue entregada desde una caché. Es un hallazgo informativo.",
        "Sin acción necesaria; verificar que el contenido sensible no se almacene en cachés compartidas.",
    ),
    "timestamp disclosure - unix": (
        "Divulgación de marcas de tiempo (Unix)",
        "La respuesta contiene valores que parecen marcas de tiempo Unix. Pueden revelar la hora del servidor o datos internos.",
        "Revisar manualmente que esos valores no expongan información sensible.",
    ),
    "information disclosure - suspicious comments": (
        "Divulgación de información: comentarios sospechosos",
        "La respuesta contiene comentarios (por ejemplo TODO, FIXME, usuario o contraseña) que podrían dar pistas útiles a un atacante.",
        "Eliminar comentarios y código de depuración de las respuestas de producción.",
    ),
    "information disclosure - debug error messages": (
        "Divulgación de información: mensajes de depuración",
        "La respuesta contiene mensajes de depuración o de error que pueden revelar detalles internos de la aplicación.",
        "Desactivar el modo de depuración en producción y mostrar mensajes de error genéricos.",
    ),
    "information disclosure - sensitive information in url": (
        "Divulgación de información: datos sensibles en la URL",
        "La URL contiene datos que podrían ser sensibles (por ejemplo sesiones o credenciales), y las URL quedan en registros, historiales y cabeceras Referer.",
        "No enviar datos sensibles en la URL; usar el cuerpo de la solicitud o cabeceras.",
    ),
    "application error disclosure": (
        "Divulgación de errores de la aplicación",
        "La página muestra un mensaje de error o una traza que puede revelar información sensible, como rutas, versiones o consultas.",
        "Mostrar errores genéricos al usuario y registrar el detalle solo en el servidor.",
    ),
    "permissions policy header not set": (
        "Falta la cabecera Permissions-Policy",
        "Permissions-Policy permite controlar qué funciones del navegador (cámara, micrófono, geolocalización, etc.) pueden usar la página y los marcos incrustados.",
        "Enviar la cabecera Permissions-Policy limitando las funciones a las que realmente se usan.",
    ),
    "absence of anti-csrf tokens": (
        "Ausencia de tokens anti-CSRF",
        "No se detectaron tokens anti-CSRF en un formulario HTML. Un atacante podría lograr que un usuario autenticado envíe solicitudes no deseadas (CSRF).",
        "Usar tokens anti-CSRF únicos por sesión en los formularios y cookies con SameSite.",
    ),
    "cross-domain javascript source file inclusion": (
        "Inclusión de JavaScript desde otro dominio",
        "La página carga scripts desde dominios externos. Si alguno de ellos fuera comprometido, se ejecutaría código malicioso en este sitio.",
        "Alojar los scripts propios, usar integridad de subrecursos (SRI) y confiar solo en los dominios necesarios.",
    ),
    "sub resource integrity attribute missing": (
        "Falta el atributo de integridad de subrecursos (SRI)",
        "Hay scripts u hojas de estilo externos cargados sin el atributo integrity, por lo que no se detectaría si fueran alterados.",
        "Agregar los atributos integrity y crossorigin a los recursos externos.",
    ),
    "insufficient site isolation against spectre vulnerability": (
        "Aislamiento de sitio insuficiente frente a Spectre",
        "Faltan cabeceras (Cross-Origin-Resource-Policy, Cross-Origin-Embedder-Policy y Cross-Origin-Opener-Policy) que aíslan el sitio frente a ataques de tipo Spectre.",
        "Enviar las cabeceras CORP, COEP y COOP según corresponda a la aplicación.",
    ),
    "session management response identified": (
        "Respuesta de gestión de sesión identificada",
        "ZAP identificó una respuesta que establece o usa una sesión. Es un hallazgo informativo.",
        "Sin acción necesaria.",
    ),
    "content-type header missing": (
        "Falta la cabecera Content-Type",
        "La respuesta no declara su Content-Type, por lo que el navegador debe adivinar el tipo de contenido.",
        "Enviar un Content-Type correcto, con su charset, en todas las respuestas.",
    ),
    "big redirect detected (potential sensitive information leak)": (
        "Redirección grande detectada (posible fuga de información)",
        "La respuesta de redirección es inusualmente grande y podría incluir información sensible en su cuerpo.",
        "Revisar que las redirecciones no contengan datos sensibles en el cuerpo.",
    ),
    "vulnerable js library": (
        "Biblioteca JavaScript vulnerable",
        "La página usa una biblioteca JavaScript con vulnerabilidades conocidas.",
        "Actualizar la biblioteca a la última versión estable.",
    ),
    "directory browsing": (
        "Listado de directorios habilitado",
        "El servidor muestra el contenido de un directorio, lo que expone archivos que no debieran ser públicos.",
        "Desactivar el listado de directorios en el servidor web.",
    ),
    "sql injection": (
        "Inyección SQL",
        "Es posible alterar las consultas a la base de datos mediante datos de entrada, lo que podría exponer o modificar información.",
        "Usar consultas parametrizadas y validar todas las entradas.",
    ),
    "cross site scripting (reflected)": (
        "Cross-Site Scripting (XSS) reflejado",
        "Datos de entrada se devuelven en la página sin una codificación adecuada, lo que permite ejecutar scripts en el navegador de la víctima.",
        "Validar la entrada y codificar la salida según el contexto (HTML, atributo, JavaScript); usar una política CSP.",
    ),
    "cross site scripting (persistent)": (
        "Cross-Site Scripting (XSS) persistente",
        "Datos almacenados por la aplicación se muestran a otros usuarios sin codificación adecuada, permitiendo ejecutar scripts en sus navegadores.",
        "Validar la entrada, codificar la salida según el contexto y usar una política CSP.",
    ),
    "path traversal": (
        "Recorrido de rutas (Path Traversal)",
        "Es posible acceder a archivos fuera del directorio previsto manipulando rutas de archivo.",
        "Validar y normalizar las rutas, y no construir rutas de archivo con datos del usuario.",
    ),
    "remote os command injection": (
        "Inyección de comandos del sistema operativo",
        "Es posible ejecutar comandos del sistema operativo mediante datos de entrada.",
        "No pasar datos del usuario a comandos del sistema; usar listas de valores permitidos.",
    ),
}

_ESPACIOS = re.compile(r"\s+")


def _clave(nombre: str) -> str:
    return _ESPACIOS.sub(" ", (nombre or "").replace("“", '"').replace("”", '"')).strip().lower()


def traducir(alerta: Dict) -> Optional[Entrada]:
    """Devuelve (nombre, descripción, recomendación) en español si la alerta está en el catálogo."""
    return CATALOGO.get(_clave(alerta.get("alert") or alerta.get("name") or ""))
