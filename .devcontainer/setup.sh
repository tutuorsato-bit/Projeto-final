#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

if ! grep -q '^SECRET_KEY=.' .env; then
  secret_key="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
  sed -i "s/^SECRET_KEY=.*/SECRET_KEY=${secret_key}/" .env
fi

chmod 600 .env
python -m pip install -r requirements.txt
