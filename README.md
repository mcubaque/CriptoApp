# Cripto App

App web interactiva para aprender criptografía viendo el **proceso paso a paso**, no solo el
resultado final. Cubre criptografía clásica, simétrica moderna (versiones didácticas de DES/AES),
asimétrica (RSA, Diffie-Hellman, firmas, ataques, cripto híbrida), PKI (certificados, anillos de
confianza) y autenticación (hash/HMAC, cracking de contraseñas, biométricos) — el mapa completo del
módulo de posgrado "Criptografía II" (8/8 escenarios cubiertos).

## Stack

- Flask (app factory) + Jinja2 + HTMX + Alpine.js (sin build de Node, todo servido localmente)
- PostgreSQL vía Docker Compose (historial de operaciones)
- Casi ninguna librería de criptografía externa: toda la aritmética (gcd, inversos modulares,
  exponenciación modular, GF(2⁴)...) está escrita a mano en `app/core/numeric_utils.py`. La única
  excepción deliberada es el hashing (`hashlib`/`hmac` de la librería estándar de Python) — ver
  la nota en `app/algorithms/authentication/hash_demo.py` sobre por qué no se reimplementó SHA-256
  a mano como sí se hizo con S-DES/S-AES.

## Algoritmos incluidos

| Familia | Algoritmos |
|---|---|
| Clásica | Desplazamiento (César), Afín, Transposición, Sustitución monoalfabética — con criptoanálisis por frecuencias interactivo (gráfica de barras incluida) para los tres primeros |
| Simétrica moderna | S-DES (con diagrama visual de la red Feistel), S-AES |
| Asimétrica | RSA, Diffie-Hellman, Firmas digitales, Ataques a RSA (factorización, módulo común, Wiener), Criptografía híbrida (RSA + S-AES) |
| PKI y Certificados | Certificados digitales (emitir/verificar, cadena de 3 niveles), Anillos de confianza (web of trust estilo PGP) |
| Autenticación | Funciones hash + HMAC, Cracking de contraseñas (diccionario, fuerza bruta, sal), Biométricos (Hamming, curva FAR/FRR) |

Cada algoritmo de simétrica moderna y asimétrica fue verificado paso a paso contra ejemplos
académicos publicados o vectores públicos conocidos (ver `tests/algorithms/`), y los de
criptografía clásica contra los ejemplos exactos de
`Semestre 1/Criptografia Simetrica/lectura-fundamental.md`. Cada página incluye, además de la
traza, un bloque desplegable "¿por qué funciona esto matemáticamente?" con la justificación formal.

## Arranque en Windows / PowerShell

Requisitos: Python 3.11+, Docker Desktop.

```powershell
cd cripto-app

# 1. Entorno virtual e instalación de dependencias
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Variables de entorno
copy .env.example .env

# 3. Levantar Postgres (nota: usa el puerto 5433 en el host para no chocar
#    con un servicio de PostgreSQL nativo que ya pueda estar corriendo en el 5432)
docker compose up -d db

# 4. Crear las tablas
python scripts\init_db.py

# 5. Arrancar la app
python run.py
```

Abre http://127.0.0.1:5000

## Pruebas

```powershell
pytest tests\algorithms -v
```

68 tests cubren los 16 módulos de algoritmos, incluyendo los ejemplos exactos de la lectura del
curso y vectores/ejemplos de referencia externos verificables (SHA-256, S-DES, S-AES, RSA clásico,
Diffie-Hellman clásico).

## Detener

```powershell
docker compose down
```

(Esto no afecta ningún PostgreSQL nativo que tengas instalado aparte — el contenedor usa un
volumen y puerto propios.)

## Estructura

```
app/
  core/            step_trace.py (abstracción común), numeric_utils.py, text_utils.py, history_service.py
  algorithms/      lógica pura de cada algoritmo (sin Flask), testeable con pytest
  blueprints/      rutas Flask, delgadas: parsean el form, llaman al algoritmo, guardan historial
  templates/       Jinja2 + un único partial genérico (_step_trace.html) que renderiza la traza
                    de cualquier algoritmo
  static/          htmx.js y alpine.js vendorizados, CSS propio
scripts/           init_db.py
tests/algorithms/  pytest, verificado contra la lectura del curso y fuentes académicas externas
```

## Cobertura del módulo "Criptografía II" (posgrado)

| Escenario del curso | Página en la app |
|---|---|
| 1. Claves públicas, cripto híbrida | `/asimetrica/`, `/asimetrica/hibrida` |
| 2. Intercambio de claves, RSA | `/asimetrica/rsa`, `/asimetrica/diffie-hellman` |
| 3. Firmas digitales | `/asimetrica/firmas` |
| 4. Certificados digitales | `/pki/certificados` |
| 5. PKI / Anillos de confianza | `/pki/confianza` |
| 6. Ataques teóricos y reales | `/asimetrica/rsa-ataques` |
| 7. Biométricos | `/autenticacion/biometricos` |
| 8. Cracking de password | `/autenticacion/passwords` (+ `/autenticacion/hash` como base) |

## Próximos pasos posibles (fuera de alcance por ahora)

- Visualizador de modos de operación (ECB vs CBC) con AES real, para mostrar fuga de patrones.
- Vigenère, Playfair, Hill (criptografía clásica adicional).
- Diagrama visual para S-AES (hoy solo S-DES tiene diagrama de red Feistel).
- Cuentas de usuario si la app deja de ser de un solo estudiante.
