#!/bin/sh
# Run by the official nginx entrypoint (/docker-entrypoint.d) before nginx starts.
# Starts a background loop that reloads nginx whenever the backend publishes a new CRL:
# nginx only reads ssl_crl at start-up / reload.
set -eu

CRL=/etc/nginx/crl/crl-bundle.pem

(
  last=""
  while true; do
    if [ -f "$CRL" ]; then
      current=$(md5sum "$CRL" | cut -d' ' -f1)
      if [ -n "$last" ] && [ "$current" != "$last" ]; then
        if nginx -t -q 2>/dev/null; then
          nginx -s reload && echo "[crl-watch] $(date -u +%FT%TZ) CRL changed, nginx reloaded"
        else
          echo "[crl-watch] $(date -u +%FT%TZ) new CRL rejected by nginx -t, keeping the previous one" >&2
        fi
      fi
      last="$current"
    fi
    sleep 2
  done
) &

echo "[crl-watch] watching $CRL"
