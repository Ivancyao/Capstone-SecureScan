# Resultados de rendimiento sobre PostgreSQL

Medición del 08-11-2026 con `backend/tools/rendimiento.py` contra **PostgreSQL 16.15** (conexión por socket local, sin red, un solo usuario),
en un contenedor Linux distinto del equipo de desarrollo original. Para comparar en igualdad de condiciones se ejecutó el mismo script contra
SQLite en esa misma máquina. Conclusión: PostgreSQL rinde igual que SQLite (diferencia cercana al 10 %); los tiempos absolutos son mayores que los
del 26-10 (`rendimiento_resultados.md`) porque el equipo es otro. Con 6.000 evaluaciones el listado `?ultimas=10` queda en 1,0 a 1,1 s
(límite del criterio RNF-07) y el panel en 180 ms; con 1.000 evaluaciones, en unos 300 ms y 31 ms.

Mediana en ms (escala mediana: 1.000 evaluaciones; grande: 6.000):

| Medición | SQLite 26-10 | SQLite 08-11 | PostgreSQL 08-11 |
|---|---|---|---|
| Panel `/metricas`, 1.000 ev. | 19,0 | 28,1 | 30,7 |
| Listado `?ultimas=10`, 1.000 ev. | 122,0 | 302,1 | 297,7 |
| Panel `/metricas`, 6.000 ev. | 79,8 | 130,0 | 179,7 |
| Listado `?ultimas=10`, 6.000 ev. | 479,2 | 1.009,6 | 1.076,4 |
| Listado completo, 6.000 ev. | 1.034 | 2.044,2 | 2.271,6 |

Salida completa del script:

# Resultados de rendimiento

Motor de base de datos: **postgresql** · 15 repeticiones por medición · tiempos en milisegundos (incluye la pila completa de la API, sin red).


## Escala pequeña: 3 proyectos, 9 activos, 36 evaluaciones, 154 hallazgos

| Endpoint | Mediana | p95 | Máximo | Tamaño respuesta |
|---|---|---|---|---|
| POST /auth/login (bcrypt, 1 vez) | 400 | — | — | — |
| GET /proyectos | 5.6 | 8.0 | 9.8 | 1 KB |
| GET /activos | 7.4 | 9.3 | 9.3 | 2 KB |
| GET /metricas | 16.1 | 18.6 | 30.2 | 1 KB |
| GET /evaluaciones/{id} | 8.8 | 15.1 | 66.2 | 1 KB |
| GET /evaluaciones?ultimas=10 | 16.8 | 18.8 | 21.2 | 81 KB |
| GET /evaluaciones | 15.1 | 16.3 | 16.4 | 81 KB |
| POST /proyectos/{id}/reportes (PDF, 10 evaluaciones) | 182 | — | — | 7 KB |

## Escala mediana: 10 proyectos, 100 activos, 1000 evaluaciones, 4532 hallazgos

| Endpoint | Mediana | p95 | Máximo | Tamaño respuesta |
|---|---|---|---|---|
| POST /auth/login (bcrypt, 1 vez) | 316 | — | — | — |
| GET /proyectos | 6.1 | 7.0 | 7.2 | 2 KB |
| GET /activos | 9.2 | 9.5 | 9.7 | 21 KB |
| GET /metricas | 30.7 | 38.5 | 39.1 | 1 KB |
| GET /evaluaciones/{id} | 8.9 | 9.5 | 10.1 | 1 KB |
| GET /evaluaciones?ultimas=10 | 297.7 | 382.0 | 398.1 | 2358 KB |
| GET /evaluaciones | 298.5 | 330.9 | 335.2 | 2358 KB |
| POST /proyectos/{id}/reportes (PDF, 10 evaluaciones) | 103 | — | — | 7 KB |

## Escala grande: 20 proyectos, 300 activos, 6000 evaluaciones, 27095 hallazgos

| Endpoint | Mediana | p95 | Máximo | Tamaño respuesta |
|---|---|---|---|---|
| POST /auth/login (bcrypt, 1 vez) | 310 | — | — | — |
| GET /proyectos | 5.2 | 6.6 | 7.0 | 4 KB |
| GET /activos | 14.0 | 14.6 | 14.7 | 63 KB |
| GET /metricas | 179.7 | 222.8 | 275.7 | 1 KB |
| GET /evaluaciones/{id} | 11.1 | 13.8 | 14.1 | 1 KB |
| GET /evaluaciones?ultimas=10 | 1076.4 | 1183.4 | 1189.1 | 7136 KB |
| GET /evaluaciones | 2271.6 | 2892.3 | 2924.0 | 14101 KB |
| POST /proyectos/{id}/reportes (PDF, 10 evaluaciones) | 119 | — | — | 7 KB |
