#!/usr/bin/env python3
"""Saneamiento de telemetria_envios.csv -> telemetria_limpia.csv
Calcula SHA-256 antes y después y registra cuántas filas elimina cada regla.

-instalar pandas si es necesario en el entorno - pip install
"""
import hashlib
from pathlib import Path

import pandas as pd

RAIZ_PROYECTO = Path(__file__).resolve().parents[1]
ENTRADA = RAIZ_PROYECTO / "datos" / "telemetria_envios.csv"
SALIDA = RAIZ_PROYECTO / "datos" / "telemetria_limpia.csv"

ESTADOS_VALIDOS = {"ENTREGADO", "EN_TRANSITO", "EN_REPARTO", "INCIDENCIA_REPARTO"}
TEMP_MIN, TEMP_MAX = -25.0, 25.0   # rango razonable para compartimento refrigerado


def obtener_sha256(ruta_fichero):
    sha = hashlib.sha256()
    with open(ruta_fichero, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            sha.update(bloque)
    return sha.hexdigest()


def main():
    hash_antes = obtener_sha256(ENTRADA)
    print(f"SHA-256 original : {hash_antes}")

    df = pd.read_csv(ENTRADA, encoding="utf-8")
    print(f"Filas originales : {len(df)}")

    # 1. Duplicados exactos
    n = len(df)
    df = df.drop_duplicates()
    print(f"Duplicados eliminados      : {n - len(df)}")

    # 2. Nulos en campos clave
    n = len(df)
    df = df.dropna(subset=["peso_kg", "temp_celsius", "destino"])
    print(f"Filas con nulos eliminadas : {n - len(df)}")

    # 3. Valores fuera de rango / inconsistentes
    n = len(df)
    df = df[df["peso_kg"] > 0]
    print(f"Pesos no positivos         : {n - len(df)}")

    n = len(df)
    df = df[df["temp_celsius"].between(TEMP_MIN, TEMP_MAX)]
    print(f"Temperaturas anómalas      : {n - len(df)}")

    n = len(df)
    df = df[df["estado_envio"].isin(ESTADOS_VALIDOS)]
    print(f"Estados no catalogados     : {n - len(df)}")

    # Guardar (saltos de línea fijos para que el hash sea reproducible)
    df.to_csv(SALIDA, index=False, encoding="utf-8", lineterminator="\n")
    print(f"Filas finales    : {len(df)}")

    hash_despues = obtener_sha256(SALIDA)
    print(f"SHA-256 limpio   : {hash_despues}")
    print("Hash modificado  :", hash_antes != hash_despues)


if __name__ == "__main__":
    main()
