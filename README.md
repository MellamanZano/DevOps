# Lab 2: integridad y despliegue de HDFS

Este repositorio contiene el script de saneamiento, los CSV de entrada y salida, las evidencias de la práctica y el entorno de contenedores de Lab 1 dentro de `Zanoni/`.

```text
README.md
scripts/
  saneamiento.py
datos/
  telemetria_envios.csv
  telemetria_limpia.csv
evidencias/
  01_hashes_sha256.png
  02_jps_servicios.png
  03_hdfs_comandos_fsck.png
  04_webui_hdfs_browse.png
Zanoni/
  docker-compose.yml
  Dockerfile.jupyter
  notebooks/
```

## 1. Integridad — Módulo 5075

Ejecuta el proceso desde cualquier directorio con:

```powershell
python scripts\saneamiento.py
```

El script resuelve las rutas a partir de su ubicación, elimina duplicados exactos y registros con campos clave nulos, peso no positivo, temperatura fuera de `-25` a `25 °C` o estado no catalogado. En esta ejecución partió de 300 filas y produjo 292; se descartaron 2 duplicados, 3 filas con nulos, 1 peso no positivo, 1 temperatura anómala y 1 estado no catalogado.

| Fichero | SHA-256 | Filas |
|---|---|---:|
| `datos/telemetria_envios.csv` (antes) | `4471c18a0284b3aa5b32a0713e691e3c7fcadae402f105e901c7c57f49474911` | 300 |
| `datos/telemetria_limpia.csv` (después) | `f7af6b30a4067ea69c553a47db90d133380a9127224bf0c1fce830ddca58afae` | 292 |

Los hashes difieren porque el CSV de salida contiene únicamente los registros que superaron las reglas de saneamiento. Si cambia el fichero de entrada o el código, vuelve a ejecutar el script y actualiza estos valores y la captura de evidencia.

## 2. Despliegue y HDFS — Módulo 5074

El `docker-compose.yml` está en `Zanoni/`; monta el directorio raíz `datos/` del repositorio en `/workspace` dentro del NameNode. Para comprobar y arrancar HDFS y YARN:

```powershell
docker compose -f Zanoni\docker-compose.yml config --quiet
docker compose -f Zanoni\docker-compose.yml up -d namenode datanode resourcemanager nodemanager
docker compose -f Zanoni\docker-compose.yml ps
```

Puertos publicados: NameNode web `9870`, RPC `8020`, DataNode web `9864`, ResourceManager web `8088` y NodeManager web `8042`. La interfaz del NameNode está en `http://localhost:9870`.

Carga y comprueba el CSV saneado:

```powershell
docker compose -f Zanoni\docker-compose.yml exec namenode hdfs dfs -mkdir -p /empresa/logistica/input
docker compose -f Zanoni\docker-compose.yml exec namenode hdfs dfs -put -f /workspace/telemetria_limpia.csv /empresa/logistica/input/
docker compose -f Zanoni\docker-compose.yml exec namenode hdfs dfs -ls -h /empresa/logistica/input
docker compose -f Zanoni\docker-compose.yml exec namenode hdfs fsck /empresa/logistica/input/telemetria_limpia.csv -files -blocks
```

La comprobación de esta entrega encontró el fichero de 36.046 bytes con un bloque válido y sin bloques ausentes o corruptos. El informe global de HDFS también señaló bloques infrareplicados de otros ficheros preexistentes; consulta la salida de `fsck` antes de interpretar el estado del clúster completo.

## 3. Análisis crítico

HDFS divide los ficheros en bloques y, en un clúster de producción, guarda varias réplicas de cada bloque en distintos DataNodes, idealmente distribuidos entre racks. Si un DataNode deja de enviar heartbeats, el NameNode lo marca como no disponible y los clientes pueden leer el bloque desde otra réplica. Las sumas de comprobación permiten detectar una réplica dañada; HDFS la evita y puede volver a replicar el bloque desde una copia válida para recuperar el factor configurado.

Apagar un DataNode no implica por sí mismo perder el fichero, siempre que quede al menos una réplica íntegra y el clúster tenga capacidad para recuperarla. No es una garantía absoluta: con factor de replicación 1, con todas las réplicas inaccesibles o dañadas, o si se pierde también el almacenamiento del NameNode sin respaldo de sus metadatos, los datos pueden quedar inaccesibles o perderse. Este entorno de práctica tiene un solo DataNode y replica los datos con factor 1, por lo que sirve para verificar comandos y bloques, no para demostrar tolerancia real a fallos.

## 4. Documentacion sobre el como se llego hasta aqui

Estructura/evidencias del proceso para hacer esta practica :
<img width="687" height="511" alt="Captura de pantalla 2026-11-10 170419" src="https://github.com/user-attachments/assets/48565311-5618-41ba-8714-8d3ed12ebfd9" />


<img width="661" height="237" alt="Captura de pantalla 2026-11-10 170503" src="https://github.com/user-attachments/assets/ac2166b2-5ce9-4333-bf07-04992760a4e5" />

<img width="1043" height="696" alt="Captura de pantalla 2026-11-10 171247" src="https://github.com/user-attachments/assets/ff9e16e2-83c0-42b7-9ba2-909e0cb45788" />


Se crea el script para generar el SHA-256, y realizar el control de calidad en python, –hay que tener pandas en el entorno:


    #!/usr/bin/env python3
    """Saneamiento de telemetria_envios.csv -> telemetria_limpia.csv
    Calcula SHA-256 antes y después y registra cuántas filas elimina cada regla.
    """
    import hashlib
    import pandas as pd

    ENTRADA = "datos/telemetria_envios.csv"
    SALIDA = "datos/telemetria_limpia.csv"

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


<img width="773" height="218" alt="Captura de pantalla 2026-11-10 171958" src="https://github.com/user-attachments/assets/ac202b85-c498-4554-9c54-7e23d086ebb9" />



<img width="635" height="283" alt="Captura de pantalla 2026-11-10 170911" src="https://github.com/user-attachments/assets/59271b8d-0ebb-4aae-85e3-75f4ea9cc568" />

Entorno :
<img width="945" height="356" alt="Captura de pantalla 2026-11-10 170444" src="https://github.com/user-attachments/assets/8d753f10-6c9a-483b-a3f1-dc6f83e21c27" />


<img width="1056" height="740" alt="Captura de pantalla 2026-11-10 173258" src="https://github.com/user-attachments/assets/edc52caa-85e5-4d51-8a14-2bc0783a0c81" />

Problemas con jps, me pregunto porque 
“””
la imagen oficial apache/hadoop:3.4.0 incluye JRE (Java Runtime Environment) y no un JDK (Java Development Kit). La utilidad jps (Java Virtual Machine Process Status Tool) solo forma parte del JDK, por lo que el archivo binario no existe físicamente dentro del contenedor. 
“””

Para la ingesta de datos se entra al namenode: 


<img width="668" height="49" alt="Captura de pantalla 2026-11-10 173734" src="https://github.com/user-attachments/assets/f6c9b671-ad66-4b08-a8c5-8578169a2500" />



<img width="594" height="106" alt="image" src="https://github.com/user-attachments/assets/6ca0ed88-9f7b-45bd-b825-cd6ea8a0db84" />


<img width="711" height="97" alt="image" src="https://github.com/user-attachments/assets/e6b00126-48a5-4f50-aa70-e6419da53631" />

<img width="876" height="60" alt="image" src="https://github.com/user-attachments/assets/730cefab-79a7-4e08-90e7-79551cce1afd" />

<img width="1058" height="244" alt="image" src="https://github.com/user-attachments/assets/d4490d10-8374-4e4e-b0d3-4ec660e62266" />

El resto del trabajo conciste en cambiar la estructura del projecto para entregar lo que se pide ...

Se audita :
<img width="1052" height="901" alt="image" src="https://github.com/user-attachments/assets/e60b828b-e79f-4ecb-918c-d61862966d80" />

<img width="782" height="82" alt="image" src="https://github.com/user-attachments/assets/d6e1c9f1-c0ac-4c86-9306-4ac4f3e45d0c" />
