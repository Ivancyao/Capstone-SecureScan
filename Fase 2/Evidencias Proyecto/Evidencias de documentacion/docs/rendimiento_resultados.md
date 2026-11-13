# Resultados de rendimiento

Motor de base de datos: **sqlite** · 15 repeticiones por medición · tiempos en milisegundos (incluye la pila completa de la API, sin red).


## Hallazgo de la prueba y corrección aplicada

La primera medición mostró un problema real: `GET /evaluaciones` cargaba los hallazgos de cada evaluación con una consulta por evaluación (patrón N+1). Con 6.000 evaluaciones tardaba **20 segundos** (14 MB), y la interfaz repite esa consulta cada 2 segundos mientras corre un escaneo.

| Escala | Antes (mediana) | Con carga anticipada (`selectinload`) | Con carga anticipada + `?ultimas=10` |
|---|---|---|---|
| Mediana (1.000 evaluaciones) | 809 ms | 121 ms | 122 ms (aún caben todas) |
| Grande (6.000 evaluaciones) | 20.066 ms | 1.034 ms | 479 ms (7 MB en vez de 14 MB) |

Correcciones: (1) los hallazgos se cargan en una sola consulta adicional; (2) el listado acepta `?ultimas=N` (las N evaluaciones más recientes por activo), y la interfaz pide 10; el panel no pierde exactitud porque `/metricas` agrega sobre todo el historial en la base de datos.

## Limitaciones de esta medición

- Esta medición se hizo sobre **SQLite**, en archivo local y sin red. El 08-11-2026 se repitió sobre PostgreSQL 16 y dio resultados equivalentes (ver `rendimiento_postgresql.md`); el script `backend/tools/rendimiento.py` se puede ejecutar contra PostgreSQL con `DATABASE_URL` (usa una base de pruebas: borra y recrea las tablas).
- El tamaño de la escala grande (300 activos, 27.000 hallazgos) supera lo esperable para una pyme; sirve para ver cómo crece el costo, no como carga real.
- Medido con un solo usuario; no es una prueba de concurrencia.
- Pendiente a futuro: paginar `GET /evaluaciones` y consultar solo las evaluaciones en curso mientras se espera un escaneo.

# Mediciones

## Escala pequeña: 3 proyectos, 9 activos, 36 evaluaciones, 154 hallazgos

| Endpoint | Mediana | p95 | Máximo | Tamaño respuesta |
|---|---|---|---|---|
| POST /auth/login (bcrypt, 1 vez) | 308 | — | — | — |
| GET /proyectos | 4.6 | 5.5 | 16.7 | 1 KB |
| GET /activos | 5.2 | 7.5 | 8.8 | 2 KB |
| GET /metricas | 11.4 | 15.6 | 33.9 | 1 KB |
| GET /evaluaciones/{id} | 6.2 | 9.9 | 14.0 | 1 KB |
| GET /evaluaciones?ultimas=10 | 10.1 | 11.8 | 18.3 | 81 KB |
| GET /evaluaciones | 11.5 | 12.4 | 12.5 | 81 KB |
| POST /proyectos/{id}/reportes (PDF, 10 evaluaciones) | 76 | — | — | 7 KB |

## Escala mediana: 10 proyectos, 100 activos, 1000 evaluaciones, 4532 hallazgos

| Endpoint | Mediana | p95 | Máximo | Tamaño respuesta |
|---|---|---|---|---|
| POST /auth/login (bcrypt, 1 vez) | 234 | — | — | — |
| GET /proyectos | 4.8 | 5.3 | 6.5 | 2 KB |
| GET /activos | 6.3 | 6.7 | 6.9 | 21 KB |
| GET /metricas | 19.0 | 23.6 | 24.2 | 1 KB |
| GET /evaluaciones/{id} | 6.3 | 6.7 | 7.1 | 1 KB |
| GET /evaluaciones?ultimas=10 | 122.0 | 185.4 | 199.2 | 2358 KB |
| GET /evaluaciones | 127.6 | 177.8 | 183.5 | 2358 KB |
| POST /proyectos/{id}/reportes (PDF, 10 evaluaciones) | 79 | — | — | 7 KB |

## Escala grande: 20 proyectos, 300 activos, 6000 evaluaciones, 27095 hallazgos

| Endpoint | Mediana | p95 | Máximo | Tamaño respuesta |
|---|---|---|---|---|
| POST /auth/login (bcrypt, 1 vez) | 238 | — | — | — |
| GET /proyectos | 6.8 | 7.2 | 9.6 | 4 KB |
| GET /activos | 12.6 | 14.7 | 14.9 | 63 KB |
| GET /metricas | 79.8 | 92.8 | 107.8 | 1 KB |
| GET /evaluaciones/{id} | 8.8 | 9.6 | 10.0 | 1 KB |
| GET /evaluaciones?ultimas=10 | 479.2 | 547.0 | 562.3 | 7136 KB |
| GET /evaluaciones | 1005.0 | 1125.2 | 1167.5 | 14101 KB |
| POST /proyectos/{id}/reportes (PDF, 10 evaluaciones) | 119 | — | — | 7 KB |


## Paginación de `GET /evaluaciones` (09-11-2026)

Se agregaron los parámetros `pagina` y `por_pagina` (máx. 200); el total viaja en la cabecera `X-Total-Count`. Sin `pagina` la respuesta es la de siempre. Medición en el mismo equipo y con la misma semilla (SQLite, mediana de 15 repeticiones, ms):

| Endpoint (escala grande, 6.000 evaluaciones) | Mediana | p95 | Tamaño respuesta |
|---|---|---|---|
| `GET /evaluaciones` (todo) | 1.933 | 2.231 | 14.101 KB |
| `GET /evaluaciones?ultimas=10` | 810 | 1.135 | 7.136 KB |
| `GET /evaluaciones?pagina=1&por_pagina=50` | 28,2 | 31,5 | 109 KB |
| `GET /evaluaciones?pagina=60&por_pagina=50` | 30,5 | 34,1 | 110 KB |

Con 1.000 evaluaciones la primera página tarda 18,4 ms (contra 203,8 ms de `?ultimas=10`). El tiempo ya no crece con el volumen total, solo con el tamaño de la página, y queda muy por debajo del límite de 1 s del RNF-07.
Nota: en esta corrida el equipo estuvo más cargado que en la anterior (listado completo 1.933 ms frente a 1.005 ms), por lo que las cifras de esta sección solo se comparan entre sí.
