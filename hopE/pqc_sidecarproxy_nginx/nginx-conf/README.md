# Post-Quantum Nginx Reverse Proxy für VON Network

## Übersicht

Dieser Ordner enthält die Konfiguration für einen **Post-Quantum Cryptography (PQC) enabled Nginx Reverse Proxy**, der vor dem VON Network Webserver läuft.

## Architektur

```
Client (Browser/ACA-Py)
    ↓ HTTPS (Port 4433)
    ↓ ML-KEM-768 / ML-KEM-1024 Key Exchange
    ↓ TLS 1.3
[OQS Nginx Reverse Proxy]
    ↓ HTTP (intern)
[VON Network Webserver:8000]
    ↓
[Indy Ledger Nodes]
```

## Features

### Post-Quantum Cryptography
- **ML-KEM-768**: NIST FIPS-203 empfohlener Standard
- **ML-KEM-1024**: Höhere Sicherheitsstufe
- **x25519**: Klassischer ECDH für Rückwärtskompatibilität

### TLS Konfiguration
- TLS 1.3 Only
- Quantum-safe Key Exchange
- Self-signed Zertifikate (generiert vom OQS Image)

### Reverse Proxy Features
- WebSocket Support (für Echtzeit-Ledger-Updates)
- Security Headers (HSTS, X-Frame-Options, etc.)
- Health Check Endpoint: `/health`
- Genesis File Pass-through: `/genesis`

## Verwendung

### Start
```bash
# Von-network starten (falls noch nicht laufend)
cd ../von-network
./manage start

# Hope services mit PQC Proxy starten
cd ../hopE
docker-compose up -d
```

### Zugriff

**Quantum-Safe HTTPS (empfohlen):**
```bash
# VON Network Web UI (mit PQC)
https://localhost:4433

# Genesis File (mit PQC)
https://localhost:4433/genesis

# Health Check
https://localhost:4433/health
```

**Klassisch HTTP (direkt, ohne PQC):**
```bash
# Falls von-network direkt exponiert ist
http://localhost:9000
```

### Test der PQC-Verbindung

```bash
# Mit OpenSSL prüfen (benötigt OQS-OpenSSL)
docker run --rm --network host openquantumsafe/curl \
  curl -v https://localhost:4433

# Logs ansehen
docker logs von-webserver-pqc-proxy

# Nginx Logs (im Container)
docker exec von-webserver-pqc-proxy cat /opt/nginx/logs/access.log
```

## Konfiguration

### Environment Variablen

**DEFAULT_GROUPS** (in docker-compose.yml):
```yaml
DEFAULT_GROUPS=mlkem768:x25519:mlkem1024
```

Verfügbare Gruppen (Beispiele):
- `mlkem512`, `mlkem768`, `mlkem1024` (NIST ML-KEM)
- `kyber512`, `kyber768`, `kyber1024` (Pre-standardization)
- `x25519`, `x448` (Klassisch)
- Hybrid: `p256_mlkem768`, `p384_mlkem1024`

### nginx.conf Anpassungen

Die Datei `nginx.conf` kann bei Bedarf angepasst werden:

```nginx
# Upstream ändern (falls anderer Backend-Port)
upstream von_webserver {
    server webserver:8000;
}

# Zusätzliche Locations hinzufügen
location /custom-endpoint {
    proxy_pass http://von_webserver/custom;
}
```

Nach Änderungen:
```bash
docker-compose restart von-webserver-proxy
```

## Sicherheitshinweise

⚠️ **NICHT FÜR PRODUKTION GEEIGNET**

Diese Konfiguration verwendet:
- Self-signed Zertifikate
- Keine Client-Authentifizierung
- Experimentelle PQC-Algorithmen

Für Produktionsumgebungen:
1. Verwende valide TLS-Zertifikate (Let's Encrypt, etc.)
2. Aktiviere Client-Certificate Authentication
3. Verwende nur NIST-standardisierte Algorithmen
4. Implementiere Rate Limiting
5. Aktiviere Audit Logging

## Technische Details

### OQS nginx Image
- Base: Alpine Linux
- OpenSSL: 3.4.0 mit OQS Provider
- liboqs: 0.13.0
- nginx: 1.28.0

### Port Mapping
- `4433`: HTTPS mit PQC (öffentlich)
- Intern: Verbindung zu `webserver:8000` (VON Network)

### Volumes
- `./nginx-conf/nginx.conf`: Read-only mount der Config
- `nginx-logs`: Persistent logs

## Troubleshooting

### Proxy startet nicht
```bash
# Logs prüfen
docker logs von-webserver-pqc-proxy

# Config testen
docker exec von-webserver-pqc-proxy nginx -t
```

### Verbindungsfehler
```bash
# Netzwerk prüfen
docker network inspect von_von

# Webserver erreichbar?
docker exec von-webserver-pqc-proxy wget -O- http://webserver:8000
```

### SSL-Fehler im Browser
- Browser akzeptiert self-signed Zertifikate nicht
- Lösung: Zertifikat-Warnung akzeptieren oder `-k` bei curl verwenden

## Referenzen

- [Open Quantum Safe](https://openquantumsafe.org/)
- [OQS nginx Demo](https://github.com/open-quantum-safe/oqs-demos/tree/main/nginx)
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-KEM (FIPS-203)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)

## Lizenz

Basiert auf [oqs-demos](https://github.com/open-quantum-safe/oqs-demos) (MIT License)
