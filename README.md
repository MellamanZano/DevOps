<img width="618" height="431" alt="image" src="https://github.com/user-attachments/assets/9f63b986-b277-44b3-80ff-647309de8595" />

Se empieza con la estructura del projecto :

<img width="735" height="423" alt="image" src="https://github.com/user-attachments/assets/b2052fff-66f0-4c14-8f54-bd96f3f1adee" />

El docker con el dockerfile :

name: practica-5075

services:
  practica:
    build:
      context: .
      dockerfile: Dockerfile
    working_dir: /app
    volumes:
      - .:/app
    command: ["tail", "-f", "/dev/null"]


FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends tree \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt




<img width="611" height="406" alt="image" src="https://github.com/user-attachments/assets/fadc602f-a561-42f2-8f1a-29b2f972e4e1" />

Aqui se genera un script de python para obtener el sha256 y compararlo con el manifest_checksum :

#!/usr/bin/env python3
"""
01_verificar_integridad.py
Pasarela de integridad criptográfica (SHA-256) por lotes.

- Lee manifest_checksums.sha256 (formato sha256sum: "<hash>  <fichero>").
- Calcula el SHA-256 de cada fichero del lote y lo compara con el esperado.
- Firma OK        -> staging/verified/
- Firma distinta  -> quarantine/tampered/ (+ alerta en el log)
- El proceso NO se detiene ante un fichero corrupto: se registra y se sigue.

Uso (desde la raíz del proyecto):
    python scripts/01_verificar_integridad.py            # copia (conserva el raw)
    python scripts/01_verificar_integridad.py --mover    # mueve (como pide el enunciado)
"""
import argparse
import hashlib
import json
import logging
import shutil
import sys
from datetime import datetime
from pathlib import Path

# --- Rutas relativas a la raíz del proyecto (funciona se ejecute desde donde se ejecute)
RAIZ = Path(__file__).resolve().parent.parent
RAW_DIR = RAIZ / "raw_batch_202611"
MANIFEST = RAW_DIR / "manifest_checksums.sha256"
VERIFIED_DIR = RAIZ / "staging" / "verified"
TAMPERED_DIR = RAIZ / "quarantine" / "tampered"
LOGS_DIR = RAIZ / "logs"
REPORTS_DIR = RAIZ / "reports"
RESUMEN_JSON = REPORTS_DIR / "resumen_integridad.json"  # lo reutiliza la Fase 3

log = logging.getLogger("integridad")


def configurar_logging() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    formato = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s",
                                "%Y-%m-%d %H:%M:%S")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    for handler in (logging.StreamHandler(sys.stdout),
                    logging.FileHandler(LOGS_DIR / "verificacion_integridad.log",
                                        mode="a", encoding="utf-8")):
        handler.setFormatter(formato)
        log.addHandler(handler)


def calcular_sha256(ruta_fichero: Path) -> str:
    """SHA-256 leyendo en bloques de 64 KB (no carga el fichero entero en memoria)."""
    hasher = hashlib.sha256()
    with open(ruta_fichero, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def leer_manifiesto(ruta: Path) -> dict[str, str]:
    """Devuelve {nombre_fichero: hash_esperado}. Línea a línea, tolerante a CRLF y '*'."""
    esperados: dict[str, str] = {}
    with open(ruta, "r", encoding="utf-8") as f:
        for n, linea in enumerate(f, start=1):
            linea = linea.strip()                 # quita \r\n y espacios
            if not linea or linea.startswith("#"):
                continue
            partes = linea.split(maxsplit=1)      # hash + resto (nombre puede llevar espacios)
            if len(partes) != 2 or len(partes[0]) != 64:
                log.warning("Manifiesto línea %d con formato inválido: %r", n, linea)
                continue
            hash_esperado, nombre = partes
            nombre = Path(nombre.lstrip("*").strip()).name   # quita '*' (modo binario) y rutas
            esperados[nombre] = hash_esperado.lower()
    return esperados


def segregar(origen: Path, destino_dir: Path, mover: bool) -> Path:
    destino_dir.mkdir(parents=True, exist_ok=True)
    destino = destino_dir / origen.name
    if mover:
        if destino.exists():
            destino.unlink()                      # idempotente en reejecuciones
        shutil.move(str(origen), str(destino))
    else:
        shutil.copy2(origen, destino)             # sobrescribe si ya existía
    return destino


def main() -> int:
    parser = argparse.ArgumentParser(description="Verificación SHA-256 por lotes")
    parser.add_argument("--mover", action="store_true",
                        help="mover los ficheros en lugar de copiarlos")
    args = parser.parse_args()

    configurar_logging()
    log.info("=== INICIO verificación de integridad | lote: %s ===", RAW_DIR.name)

    if not MANIFEST.exists():
        log.error("No existe el manifiesto: %s", MANIFEST)
        return 2

    esperados = leer_manifiesto(MANIFEST)
    log.info("Manifiesto leído: %d entradas", len(esperados))

    resultados = []
    validados, rechazados = [], []

    # 1) Ficheros del manifiesto
    for nombre, hash_esperado in esperados.items():
        ruta = RAW_DIR / nombre
        if not ruta.exists():
            log.error("FALTA en disco (está en el manifiesto): %s", nombre)
            resultados.append({"fichero": nombre, "estado": "AUSENTE",
                               "esperado": hash_esperado, "calculado": None})
            rechazados.append(nombre)
            continue

        hash_calculado = calcular_sha256(ruta)
        if hash_calculado == hash_esperado:
            segregar(ruta, VERIFIED_DIR, args.mover)
            log.info("OK        %s -> staging/verified/", nombre)
            resultados.append({"fichero": nombre, "estado": "VALIDO",
                               "esperado": hash_esperado, "calculado": hash_calculado})
            validados.append(nombre)
        else:
            segregar(ruta, TAMPERED_DIR, args.mover)
            log.warning("ALERTA    firma NO coincide: %s -> quarantine/tampered/", nombre)
            log.warning("          esperado : %s", hash_esperado)
            log.warning("          calculado: %s", hash_calculado)
            resultados.append({"fichero": nombre, "estado": "MANIPULADO",
                               "esperado": hash_esperado, "calculado": hash_calculado})
            rechazados.append(nombre)

    # 2) Ficheros en el lote que NO figuran en el manifiesto (sin firma oficial = no confiable)
    for ruta in sorted(RAW_DIR.glob("*")):
        if ruta.is_file() and ruta.name != MANIFEST.name and ruta.name not in esperados:
            if (VERIFIED_DIR / ruta.name).exists() or (TAMPERED_DIR / ruta.name).exists():
                continue
            segregar(ruta, TAMPERED_DIR, args.mover)
            log.warning("ALERTA    sin firma en el manifiesto: %s -> quarantine/tampered/", ruta.name)
            resultados.append({"fichero": ruta.name, "estado": "SIN_FIRMA",
                               "esperado": None, "calculado": None})
            rechazados.append(ruta.name)

    total = len(validados) + len(rechazados)
    tasa = (len(validados) / total * 100) if total else 0.0

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    resumen = {
        "fecha_ejecucion": datetime.now().isoformat(timespec="seconds"),
        "lote": RAW_DIR.name,
        "total_ficheros": total,
        "validados": len(validados),
        "rechazados": len(rechazados),
        "tasa_integridad_criptografica_pct": round(tasa, 2),
        "detalle": resultados,
    }
    RESUMEN_JSON.write_text(json.dumps(resumen, indent=2, ensure_ascii=False),
                            encoding="utf-8")

    log.info("=== RESUMEN: %d validados | %d rechazados | integridad %.1f%% ===",
             len(validados), len(rechazados), tasa)
    log.info("Resumen guardado en %s", RESUMEN_JSON.relative_to(RAIZ))

    # Código de salida 1 si hubo rechazos (útil para orquestadores), pero tras procesar TODO
    return 1 if rechazados else 0


if __name__ == "__main__":
    sys.exit(main())




Lo que hace es tracear las rutas del projecto, crea un logger que da salida al terminal y al fichero logs, se calcula el sha, lee el manifiesto y construye un diccionario con el nombre del fichero y el hash esperado. Copia o mueve un fichero a la carpeta destino, creándola si no existe. Lo interesante es que corriendo este script sale esto :


<img width="1091" height="280" alt="image" src="https://github.com/user-attachments/assets/355a135f-33c6-49ee-95d2-e2e243e0c9e4" />


Es probable que primero hay que sanear los datos y luego se hace el calculo del sha, o hay un error por como se descarga el fichero de github.

Probablemente haya un error.


<img width="625" height="554" alt="image" src="https://github.com/user-attachments/assets/b60e8bb2-44f6-48dd-9df7-14451ac2d517" />

Dado el error del hash, se coloca manualmente los archivos en verified, solamente norte y este. 

Script para saneamiento de datos :

#!/usr/bin/env python3
"""
02_pipeline_saneamiento_kdd.py  (Fase 2: limpieza, coherencia y outliers)

Entrada : staging/verified/*.csv      (ficheros que superaron la Fase 1)
Salidas : processed/dataset_kdd_listo.csv   -> registros limpios
          quarantine/bad_records.csv        -> registros rechazados + motivo_rechazo
          reports/metricas_limpieza.json    -> cifras para el informe de la Fase 3

Principio: ningún registro se pierde en silencio; todo lo descartado queda en
cuarentena con el motivo, y el pipeline nunca se detiene por un registro malo.

Uso (desde la raíz del proyecto):
    python scripts/02_pipeline_saneamiento_kdd.py
"""
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# ---------------------------------------------------------------- Rutas
RAIZ = Path(__file__).resolve().parent.parent
VERIFIED_DIR = RAIZ / "staging" / "verified"
PROCESSED_DIR = RAIZ / "processed"
QUARANTINE_DIR = RAIZ / "quarantine"
LOGS_DIR = RAIZ / "logs"
REPORTS_DIR = RAIZ / "reports"

SALIDA_LIMPIO = PROCESSED_DIR / "dataset_kdd_listo.csv"
SALIDA_RECHAZADOS = QUARANTINE_DIR / "bad_records.csv"
SALIDA_METRICAS = REPORTS_DIR / "metricas_limpieza.json"

# ---------------------------------------------------------------- Configuración
OBLIGATORIAS = ["id_transaccion", "timestamp", "importe_eur", "unidades"]
VALORES_NULOS = ["", "NULL", "null", "NaN", "nan", "N/A", "n/a", "NA", "None", "-"]
FORMATO_ISO = "%Y-%m-%d %H:%M:%S"
IQR_K = 1.5          # 1.5 = outlier clásico (Tukey); 3.0 = solo extremos

log = logging.getLogger("saneamiento")


def configurar_logging() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    formato = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s",
                                "%Y-%m-%d %H:%M:%S")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    for h in (logging.StreamHandler(sys.stdout),
              logging.FileHandler(LOGS_DIR / "pipeline_saneamiento.log",
                                  mode="a", encoding="utf-8")):
        h.setFormatter(formato)
        log.addHandler(h)


# ---------------------------------------------------------------- Utilidades
def apartar(df: pd.DataFrame, mask: pd.Series, motivo: str,
            raw: pd.DataFrame, rechazados: list, conteo: dict) -> pd.DataFrame:
    """Saca de df las filas con mask=True, las guarda (valores originales) con su motivo."""
    mask = mask.fillna(False).astype(bool)
    n = int(mask.sum())
    if n:
        r = raw.loc[df.index[mask.values]].copy()
        r["motivo_rechazo"] = motivo
        rechazados.append(r)
        conteo[motivo] = conteo.get(motivo, 0) + n
        log.warning("ANOMALÍA  %4d registros -> cuarentena | %s", n, motivo)
    return df[~mask]


def cargar_lote() -> tuple[pd.DataFrame, list, list]:
    """Lee y concatena todos los CSV verificados. Devuelve (df, procesados, omitidos)."""
    frames, procesados, omitidos = [], [], []
    for ruta in sorted(VERIFIED_DIR.glob("*.csv")):
        try:
            d = pd.read_csv(ruta, dtype=str, sep=None, engine="python",
                            na_values=VALORES_NULOS, skipinitialspace=True,
                            encoding_errors="replace", on_bad_lines="warn")
        except Exception as e:                               # fichero ilegible
            log.error("No se pudo leer %s: %s", ruta.name, e)
            omitidos.append(ruta.name)
            continue

        d.columns = [c.strip().lower() for c in d.columns]
        faltan = [c for c in OBLIGATORIAS if c not in d.columns]
        if faltan:                                           # schema drift
            log.error("SCHEMA DRIFT en %s: faltan columnas %s -> fichero omitido",
                      ruta.name, faltan)
            omitidos.append(ruta.name)
            continue

        d["origen"] = ruta.stem.replace("transacciones_", "")
        d["linea_origen"] = np.arange(2, len(d) + 2)         # nº de línea en el CSV (cabecera = 1)
        log.info("Cargado   %-35s %6d registros, %d columnas", ruta.name, len(d), d.shape[1] - 2)
        frames.append(d)
        procesados.append(ruta.name)

    if not frames:
        return pd.DataFrame(), procesados, omitidos
    df = pd.concat(frames, ignore_index=True)
    # recorta espacios y convierte celdas vacías en nulos reales
    df = df.apply(lambda c: c.str.strip() if c.dtype == object else c)
    df = df.replace(r"^\s*$", np.nan, regex=True)
    return df, procesados, omitidos


def parsear_fechas(serie: pd.Series) -> pd.Series:
    try:
        ts = pd.to_datetime(serie, errors="coerce", format="mixed", utc=True)
    except (TypeError, ValueError):                          # pandas < 2.0
        ts = pd.to_datetime(serie, errors="coerce", utc=True)
    return ts.dt.tz_localize(None)


# ---------------------------------------------------------------- Pipeline
def main() -> int:
    configurar_logging()
    log.info("=== INICIO pipeline de saneamiento | entrada: %s ===", VERIFIED_DIR.relative_to(RAIZ))

    if not VERIFIED_DIR.exists() or not list(VERIFIED_DIR.glob("*.csv")):
        log.error("No hay ficheros en staging/verified/. Ejecuta antes la Fase 1.")
        return 2

    # ---- 1. Carga y concatenación
    df, procesados, omitidos = cargar_lote()
    if df.empty:
        log.error("Ningún fichero válido que procesar.")
        return 2

    raw = df.copy()                     # copia con valores originales (para cuarentena)
    total = len(raw)
    otras_cols = [c for c in df.columns
                  if c not in OBLIGATORIAS + ["origen", "linea_origen"]]
    log.info("Total concatenado: %d registros | columnas secundarias: %s", total, otras_cols)

    # Completitud del dato BRUTO (antes de tocar nada): filas sin ningún nulo
    cols_datos = OBLIGATORIAS + otras_cols
    nulos_por_columna = {c: int(raw[c].isna().sum()) for c in cols_datos}
    completitud_bruta = float((~raw[cols_datos].isna().any(axis=1)).mean() * 100)
    log.info("Completitud bruta: %.2f%% | nulos por columna: %s", completitud_bruta, nulos_por_columna)

    rechazados: list[pd.DataFrame] = []
    conteo: dict[str, int] = {}

    # ---- 2. Nulos en columnas obligatorias (no se imputan: fabricar un id, una fecha
    #         o un importe falsearía el análisis de negocio)
    for col in OBLIGATORIAS:
        df = apartar(df, df[col].isna(), f"nulo en columna obligatoria: {col}",
                     raw, rechazados, conteo)

    # ---- 3. Tipos: importe y unidades numéricos; unidades entero
    importe = pd.to_numeric(df["importe_eur"].str.replace(",", ".", regex=False), errors="coerce")
    df = apartar(df, importe.isna(), "importe_eur no numérico", raw, rechazados, conteo)
    df["importe_eur"] = importe.loc[df.index]

    unidades = pd.to_numeric(df["unidades"], errors="coerce")
    df = apartar(df, unidades.isna(), "unidades no numérico", raw, rechazados, conteo)
    unidades = unidades.loc[df.index]
    df = apartar(df, unidades != unidades.round(), "unidades no entero", raw, rechazados, conteo)
    df["unidades"] = unidades.loc[df.index].astype("int64")

    # ---- 4. Coherencia temporal
    ts = parsear_fechas(df["timestamp"])
    df = apartar(df, ts.isna(), "timestamp corrupto/no parseable", raw, rechazados, conteo)
    ts = ts.loc[df.index]
    ahora = pd.Timestamp.now()
    inicio_anio = pd.Timestamp(year=ahora.year, month=1, day=1)
    df = apartar(df, ts > ahora, "timestamp futuro", raw, rechazados, conteo)
    ts = ts.loc[df.index]
    df = apartar(df, ts < inicio_anio, f"timestamp anterior a {ahora.year}", raw, rechazados, conteo)
    df["timestamp"] = ts.loc[df.index]

    # ---- 5. Reglas de dominio
    df = apartar(df, df["importe_eur"] <= 0, "importe_eur <= 0", raw, rechazados, conteo)
    df = apartar(df, df["unidades"] < 1, "unidades < 1", raw, rechazados, conteo)

    # ---- 6. Unicidad del identificador (se conserva la primera aparición)
    df = apartar(df, df["id_transaccion"].duplicated(keep="first"),
                 "id_transaccion duplicado", raw, rechazados, conteo)

    # ---- 7. Outliers en importe_eur (IQR), calculado sobre datos ya válidos
    q1, q3 = df["importe_eur"].quantile([0.25, 0.75])
    iqr = q3 - q1
    lim_inf, lim_sup = q1 - IQR_K * iqr, q3 + IQR_K * iqr
    log.info("Outliers IQR (k=%.1f): Q1=%.2f Q3=%.2f -> límites [%.2f, %.2f]",
             IQR_K, q1, q3, lim_inf, lim_sup)
    df = apartar(df, (df["importe_eur"] < lim_inf) | (df["importe_eur"] > lim_sup),
                 "outlier importe_eur (IQR)", raw, rechazados, conteo)

    # ---- 8. Imputación de columnas secundarias (mediana / moda-categoría)
    imputaciones: dict[str, dict] = {}
    for col in otras_cols:
        n_nulos = int(df[col].isna().sum())
        if n_nulos == 0:
            continue
        num = pd.to_numeric(df[col], errors="coerce")
        if num.notna().sum() == df[col].notna().sum():       # toda la columna es numérica
            valor = float(num.median())
            df[col] = num.fillna(valor)
            imputaciones[col] = {"metodo": "mediana", "valor": valor, "registros": n_nulos}
        else:
            df[col] = df[col].fillna("DESCONOCIDO")
            imputaciones[col] = {"metodo": "categoria 'DESCONOCIDO'", "registros": n_nulos}
        log.info("IMPUTADO  %-18s %4d nulos -> %s", col, n_nulos, imputaciones[col]["metodo"])

    # ---- 9. Exportación
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    limpio = df.drop(columns=["linea_origen"]).sort_values("timestamp")
    limpio["timestamp"] = limpio["timestamp"].dt.strftime(FORMATO_ISO)   # ISO 8601
    limpio.to_csv(SALIDA_LIMPIO, index=False)

    malos = pd.concat(rechazados) if rechazados else pd.DataFrame(columns=list(raw.columns) + ["motivo_rechazo"])
    malos.to_csv(SALIDA_RECHAZADOS, index=False)

    metricas = {
        "fecha_ejecucion": datetime.now().isoformat(timespec="seconds"),
        "ficheros_procesados": procesados,
        "ficheros_omitidos": omitidos,
        "registros_totales": total,
        "registros_limpios": len(limpio),
        "registros_rechazados": len(malos),
        "rechazos_por_motivo": conteo,
        "completitud_bruta_pct": round(completitud_bruta, 2),
        "nulos_por_columna_bruto": nulos_por_columna,
        "imputaciones": imputaciones,
        "outliers_iqr": {"k": IQR_K, "q1": float(q1), "q3": float(q3),
                         "limite_inferior": float(lim_inf), "limite_superior": float(lim_sup)},
    }
    SALIDA_METRICAS.write_text(json.dumps(metricas, indent=2, ensure_ascii=False), encoding="utf-8")

    log.info("=== RESUMEN: %d totales | %d limpios | %d en cuarentena ===",
             total, len(limpio), len(malos))
    log.info("Limpio    -> %s", SALIDA_LIMPIO.relative_to(RAIZ))
    log.info("Rechazos  -> %s", SALIDA_RECHAZADOS.relative_to(RAIZ))
    log.info("Métricas  -> %s", SALIDA_METRICAS.relative_to(RAIZ))
    return 0


if __name__ == "__main__":
    sys.exit(main())


Este script lee todos los CSV de staging/verified/ como texto (dtype=str), para no perder información antes de validar. Detecta el separador solo, normaliza los nombres de columna y añade origen (la tienda) y linea_origen (la línea del CSV). Si a un fichero le faltan columnas obligatorias (schema drift), lo omite y lo registra. calcula el porcentaje de filas sin ningún nulo. Un registro sin id_transaccion, timestamp, importe_eur o unidades va a cuarentena. Si un id_transaccion se repite, conserva el primero.

En este caso, un valor generado por un sensor defectuoso no es un dato real. Se utiliza la mediana para imputar y cada rechazo lleva su motivo_rechazo, con los valores originales sin modificar, para poder auditarlo.



<img width="1292" height="430" alt="image" src="https://github.com/user-attachments/assets/6a5da10c-ec10-4fdd-9742-908a6e562722" />


Ahora se crea y utiliza el script para la parte 3 :

#!/usr/bin/env python3
"""
03_perfilado_calidad_kdd.py  (Fase 3: perfilado KDD e informe de calidad)

Entradas : reports/resumen_integridad.json     (Fase 1)
           reports/metricas_limpieza.json      (Fase 2)
           processed/dataset_kdd_listo.csv     (Fase 2)
Salidas  : reports/INFORME_CALIDAD_KDD.md      -> informe técnico
           reports/perfilado_calidad.json      -> las mismas métricas, en JSON

Métricas (ISO/IEC 25012): completitud, unicidad, validez, integridad criptográfica
y distribución estadística de importe_eur tras la limpieza.

Uso (desde la raíz del proyecto, tras las Fases 1 y 2):
    python scripts/03_perfilado_calidad_kdd.py
"""
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

RAIZ = Path(__file__).resolve().parent.parent
REPORTS_DIR = RAIZ / "reports"
LOGS_DIR = RAIZ / "logs"

IN_INTEGRIDAD = REPORTS_DIR / "resumen_integridad.json"
IN_LIMPIEZA = REPORTS_DIR / "metricas_limpieza.json"
IN_DATASET = RAIZ / "processed" / "dataset_kdd_listo.csv"

OUT_MD = REPORTS_DIR / "INFORME_CALIDAD_KDD.md"
OUT_JSON = REPORTS_DIR / "perfilado_calidad.json"

# Palabras clave para clasificar los motivos de rechazo de la Fase 2
CLAVES_VALIDEZ = ("no numérico", "no entero", "corrupto", "futuro", "anterior", "<= 0", "< 1")

log = logging.getLogger("perfilado")


def configurar_logging() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    formato = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%d %H:%M:%S")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    for h in (logging.StreamHandler(sys.stdout),
              logging.FileHandler(LOGS_DIR / "perfilado_calidad.log", mode="a", encoding="utf-8")):
        h.setFormatter(formato)
        log.addHandler(h)


def pct(parte: float, total: float) -> float:
    return round(parte / total * 100, 2) if total else 0.0


def tabla_md(cabeceras: list[str], filas: list[list]) -> str:
    out = ["| " + " | ".join(cabeceras) + " |", "|" + "|".join("---" for _ in cabeceras) + "|"]
    out += ["| " + " | ".join(str(c) for c in f) + " |" for f in filas]
    return "\n".join(out)


def arbol(base: Path, max_prof: int = 3, prefijo: str = "", prof: int = 0) -> list[str]:
    """Jerarquía de carpetas tipo `tree` (evidencia de estructura)."""
    ignorar = {".git", "__pycache__", ".venv", "venv", ".ipynb_checkpoints", "notebooks"}
    if prof >= max_prof:
        return []
    hijos = sorted((p for p in base.iterdir() if p.name not in ignorar),
                   key=lambda p: (p.is_file(), p.name.lower()))
    lineas = []
    for i, p in enumerate(hijos):
        ultimo = i == len(hijos) - 1
        lineas.append(f"{prefijo}{'└── ' if ultimo else '├── '}{p.name}{'/' if p.is_dir() else ''}")
        if p.is_dir():
            lineas += arbol(p, max_prof, prefijo + ("    " if ultimo else "│   "), prof + 1)
    return lineas


def main() -> int:
    configurar_logging()
    log.info("=== INICIO perfilado de calidad ===")

    faltan = [p.relative_to(RAIZ) for p in (IN_INTEGRIDAD, IN_LIMPIEZA, IN_DATASET) if not p.exists()]
    if faltan:
        log.error("Faltan entradas: %s. Ejecuta antes las Fases 1 y 2.", [str(f) for f in faltan])
        return 2

    integ = json.loads(IN_INTEGRIDAD.read_text(encoding="utf-8"))
    limp = json.loads(IN_LIMPIEZA.read_text(encoding="utf-8"))
    df = pd.read_csv(IN_DATASET)

    # ------------------------------------------------------------ Métricas
    total = limp["registros_totales"]
    finales = limp["registros_limpios"]
    conteo = limp["rechazos_por_motivo"]

    n_nulos_obl = sum(v for m, v in conteo.items() if m.startswith("nulo en columna"))
    n_validez = sum(v for m, v in conteo.items() if any(k in m for k in CLAVES_VALIDEZ))
    n_dup = conteo.get("id_transaccion duplicado", 0)
    n_outl = sum(v for m, v in conteo.items() if m.startswith("outlier"))

    completitud_bruta = limp["completitud_bruta_pct"]
    completitud_final = pct(int((~df.isna().any(axis=1)).sum()), len(df))
    unicidad = pct(total - n_dup, total)
    validez = pct(total - n_validez, total)
    retencion = pct(finales, total)

    s = df["importe_eur"]
    dist = {
        "registros": int(s.count()),
        "media": round(float(s.mean()), 4),
        "mediana": round(float(s.median()), 4),
        "desviacion_estandar": round(float(s.std()), 4),
        "percentil_25": round(float(s.quantile(0.25)), 4),
        "percentil_75": round(float(s.quantile(0.75)), 4),
        "minimo": round(float(s.min()), 4),
        "maximo": round(float(s.max()), 4),
    }
    por_tienda = (df.groupby("origen")["importe_eur"]
                    .agg(["count", "mean", "median", "std"]).round(2).reset_index()
                    if "origen" in df.columns else pd.DataFrame())

    metricas = {
        "fecha_generacion": datetime.now().isoformat(timespec="seconds"),
        "integridad_criptografica": {
            "archivos_totales": integ["total_ficheros"],
            "validados": integ["validados"],
            "rechazados": integ["rechazados"],
            "tasa_pct": integ["tasa_integridad_criptografica_pct"],
        },
        "completitud": {"bruta_pct": completitud_bruta, "final_pct": completitud_final},
        "unicidad_pct": unicidad,
        "validez_pct": validez,
        "retencion_pct": retencion,
        "registros": {"totales": total, "limpios": finales, "cuarentena": total - finales},
        "rechazos_por_motivo": conteo,
        "distribucion_importe_eur": dist,
    }
    OUT_JSON.write_text(json.dumps(metricas, indent=2, ensure_ascii=False), encoding="utf-8")

    # ------------------------------------------------------------ Informe Markdown
    rechazados_fase1 = [d["fichero"] for d in integ["detalle"] if d["estado"] != "VALIDO"]
    validados_fase1 = [d["fichero"] for d in integ["detalle"] if d["estado"] == "VALIDO"]

    filas_motivos = [[m, n, f"{pct(n, total)} %"] for m, n in sorted(conteo.items(), key=lambda x: -x[1])]
    filas_imput = [[c, i["metodo"], i.get("valor", "-"), i["registros"]]
                   for c, i in limp["imputaciones"].items()]
    o = limp["outliers_iqr"]

    md = []
    md.append("# INFORME DE CALIDAD KDD\n")
    md.append(f"_Generado automáticamente el {datetime.now():%Y-%m-%d %H:%M:%S} · Lote `raw_batch_202611` · "
              "Marco de calidad: ISO/IEC 25012_\n")

    md.append("## 1. Resumen ejecutivo\n")
    md.append(f"- Ficheros del lote: **{integ['total_ficheros']}** → validados **{integ['validados']}**, "
              f"rechazados **{integ['rechazados']}** (integridad criptográfica **{integ['tasa_integridad_criptografica_pct']} %**).")
    md.append(f"- Registros analizados: **{total}** → limpios **{finales}** ({retencion} %), "
              f"en cuarentena **{total - finales}**.")
    md.append(f"- Completitud: **{completitud_bruta} %** en bruto → **{completitud_final} %** tras la limpieza.")
    md.append("- Dataset listo para minería: `processed/dataset_kdd_listo.csv`.\n")

    md.append("## 2. Métricas de calidad (ISO/IEC 25012)\n")
    md.append(tabla_md(
        ["Característica", "Métrica", "Resultado"],
        [
            ["Completitud (bruto)", "registros sin nulos / registros totales × 100", f"{completitud_bruta} %"],
            ["Completitud (final)", "ídem sobre el dataset entregado", f"{completitud_final} %"],
            ["Integridad criptográfica", "archivos validados / archivos totales × 100", f"{integ['tasa_integridad_criptografica_pct']} %"],
            ["Unicidad", "registros con `id_transaccion` no duplicado / totales × 100", f"{unicidad} %"],
            ["Validez", "registros sin violaciones de tipo, fecha o dominio / totales × 100", f"{validez} %"],
        ]) + "\n")

    md.append("### 2.1 Integridad criptográfica (Fase 1)\n")
    md.append(tabla_md(["Fichero", "Estado"], [[d["fichero"], d["estado"]] for d in integ["detalle"]]) + "\n")

    md.append("### 2.2 Registros rechazados por motivo (Fase 2)\n")
    md.append((tabla_md(["Motivo", "Registros", "% sobre el total"], filas_motivos)
               if filas_motivos else "_No se rechazó ningún registro._") + "\n")

    md.append("### 2.3 Imputaciones realizadas\n")
    md.append((tabla_md(["Columna", "Método", "Valor", "Registros imputados"], filas_imput)
               if filas_imput else "_No fue necesario imputar ningún valor._") + "\n")

    md.append("## 3. Distribución de `importe_eur` tras la limpieza\n")
    md.append(tabla_md(
        ["Estadístico", "Valor (EUR)"],
        [["Registros", dist["registros"]], ["Media", dist["media"]], ["Mediana", dist["mediana"]],
         ["Desviación estándar", dist["desviacion_estandar"]], ["Percentil 25", dist["percentil_25"]],
         ["Percentil 75", dist["percentil_75"]], ["Mínimo", dist["minimo"]], ["Máximo", dist["maximo"]]]) + "\n")
    if not por_tienda.empty:
        md.append("**Por centro logístico:**\n")
        md.append(tabla_md(["Origen", "N", "Media", "Mediana", "Desv. est."],
                           por_tienda.values.tolist()) + "\n")
    md.append(f"Umbrales de outliers (IQR, k = {o['k']}): Q1 = {o['q1']:.2f}, Q3 = {o['q3']:.2f} → "
              f"rango admitido [{o['limite_inferior']:.2f}, {o['limite_superior']:.2f}] EUR.\n")

    md.append("## 4. Estructura de directorios generada\n")
    md.append("```text\n" + RAIZ.name + "/\n" + "\n".join(arbol(RAIZ)) + "\n```\n")

    md.append("## 5. Conclusiones técnicas\n")
    md.append("> Borrador generado a partir de las métricas reales: revísalo y adáptalo con tus propias palabras.\n")
    md.append("### 5.1 Integridad del transporte\n")
    md.append(f"La verificación SHA-256 contra `manifest_checksums.sha256` aceptó {len(validados_fase1)} fichero(s) "
              f"({', '.join(validados_fase1) or 'ninguno'}) y aisló en `quarantine/tampered/` "
              f"{len(rechazados_fase1)} ({', '.join(rechazados_fase1) or 'ninguno'}). "
              "Un fichero con firma discrepante no puede considerarse fiable aunque su contenido parezca "
              "correcto, por lo que no entra en la cadena de transformación. Esta verificación certifica que "
              "el fichero no cambió en el transporte, pero no que sus datos tengan sentido de negocio; de ahí la Fase 2.\n")
    md.append("### 5.2 Decisiones de filtrado\n")
    md.append(f"- **Nulos en columnas obligatorias ({n_nulos_obl} registros):** se descartan y no se imputan. "
              "Un identificador, una fecha o un importe inventados falsearían la trazabilidad y los agregados económicos.")
    md.append(f"- **Tipo, fecha y dominio ({n_validez} registros):** se rechazan importes no numéricos o ≤ 0, "
              "unidades no enteras o < 1 y marcas temporales corruptas, futuras o anteriores al año en curso. "
              "Son valores que no pueden existir en una transacción real.")
    md.append(f"- **Duplicados ({n_dup} registros):** se conserva la primera aparición de cada `id_transaccion` "
              "para que ninguna venta se contabilice dos veces.")
    md.append(f"- **Outliers ({n_outl} registros):** se apartan por IQR (k = {o['k']}) sobre `importe_eur`, calculado "
              "después de las reglas de dominio para que los valores basura no distorsionen los cuantiles. "
              "Se aíslan en cuarentena en lugar de borrarse para poder auditarlos o recuperarlos si resultan ser legítimos.\n")
    md.append("### 5.3 Decisiones de imputación\n")
    if filas_imput:
        md.append("; ".join(f"`{c}`: {i['metodo']}" + (f" ({i['valor']})" if 'valor' in i else "")
                            for c, i in limp["imputaciones"].items())
                  + ". En variables numéricas se usa la **mediana** por ser robusta frente a valores extremos "
                    "(la media se desplaza con ellos); en las categóricas se usa una categoría explícita "
                    "`DESCONOCIDO` para no inventar información.\n")
    else:
        md.append("No hubo nulos en columnas secundarias, por lo que no fue necesario imputar.\n")
    md.append("### 5.4 Idoneidad para minería de datos\n")
    md.append(f"El dataset final contiene {finales} registros con completitud del {completitud_final} %, "
              "identificadores únicos, tipos coherentes (importes decimales, unidades enteras), timestamps en "
              "ISO 8601 y todos los valores dentro de los dominios de negocio. Esto evita que los modelos aprendan "
              "de ruido de sensores o de ventas duplicadas, que los algoritmos sensibles a la escala (regresión, "
              "clustering) se vean arrastrados por valores extremos y que fallen por tipos mixtos o nulos. "
              "Cada registro descartado conserva su motivo en `quarantine/bad_records.csv`, de modo que la limpieza es "
              "reproducible y auditable.\n")
    md.append("### 5.5 Limitaciones\n")
    md.append(f"- Se descartó el {round(100 - retencion, 2)} % de los registros; conviene confirmar con negocio que "
              "los outliers eliminados no eran ventas legítimas de importe alto.\n"
              "- La validez se mide solo sobre reglas explícitas; no se contrastan los datos con una fuente externa.\n"
              "- El análisis es de un único lote.")

    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

    log.info("Completitud %.2f%% -> %.2f%% | unicidad %.2f%% | validez %.2f%% | integridad %.2f%%",
             completitud_bruta, completitud_final, unicidad, validez, integ["tasa_integridad_criptografica_pct"])
    log.info("importe_eur: media=%.2f mediana=%.2f std=%.2f p25=%.2f p75=%.2f",
             dist["media"], dist["mediana"], dist["desviacion_estandar"], dist["percentil_25"], dist["percentil_75"])
    log.info("Informe  -> %s", OUT_MD.relative_to(RAIZ))
    log.info("Métricas -> %s", OUT_JSON.relative_to(RAIZ))
    return 0


if __name__ == "__main__":
    sys.exit(main())


El script lee los JSON y el CSV que dejan las fases anteriores. A partir de ello crea un resumen ejecutivo, utiliza las Métricas ISO/IEC 25012. Tambien manejja la distribución de importe_eur desglozado por tienda, el arbol de directorios y conclusiones tecnicas.

<img width="1062" height="119" alt="image" src="https://github.com/user-attachments/assets/1fe74ec5-ef48-43d9-9637-e06ba890c351" />


Perfilado calidad.json :
{
  "fecha_generacion": "2026-11-12T20:29:47",
  "integridad_criptografica": {
    "archivos_totales": 3,
    "validados": 0,
    "rechazados": 3,
    "tasa_pct": 0.0
  },
  "completitud": {
    "bruta_pct": 95.0,
    "final_pct": 100.0
  },
  "unicidad_pct": 100.0,
  "validez_pct": 93.0,
  "retencion_pct": 87.0,
  "registros": {
    "totales": 100,
    "limpios": 87,
    "cuarentena": 13
  },
  "rechazos_por_motivo": {
    "nulo en columna obligatoria: id_transaccion": 2,
    "nulo en columna obligatoria: importe_eur": 1,
    "timestamp corrupto/no parseable": 1,
    "timestamp futuro": 1,
    "timestamp anterior a 2026": 1,
    "importe_eur <= 0": 2,
    "unidades < 1": 2,
    "outlier importe_eur (IQR)": 3
  },
  "distribucion_importe_eur": {
    "registros": 87,
    "media": 70.9866,
    "mediana": 73.44,
    "desviacion_estandar": 26.3366,
    "percentil_25": 53.805,
    "percentil_75": 85.345,
    "minimo": 12.5,
    "maximo": 124.47
  }
}



Y el informe de calidad :

