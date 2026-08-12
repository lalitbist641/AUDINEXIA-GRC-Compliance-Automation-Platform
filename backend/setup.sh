#!/usr/bin/env bash
# One-shot setup for the Audinexia backend: venv, dependencies, .env with
# freshly generated secrets, and the initial database migration.
set -e
cd "$(dirname "$0")"

echo "== Audinexia backend setup =="

if [ ! -d "venv" ]; then
  echo "-- Creating virtual environment"
  (command -v python3 >/dev/null && python3 -m venv venv) || python -m venv venv
fi

if [ -f "venv/bin/python" ]; then
  PYTHON="venv/bin/python"
  ACTIVATE_HINT="source venv/bin/activate"
elif [ -f "venv/Scripts/python.exe" ]; then
  PYTHON="venv/Scripts/python.exe"
  ACTIVATE_HINT="source venv/Scripts/activate"
else
  echo "Could not find a python executable inside venv/. Aborting." >&2
  exit 1
fi

echo "-- Installing dependencies"
"$PYTHON" -m pip install --upgrade pip -q
"$PYTHON" -m pip install -r requirements.txt

if [ ! -f ".env" ]; then
  echo "-- Generating .env with fresh random secrets"
  SECRET_KEY=$("$PYTHON" -c "import secrets; print(secrets.token_hex(32))")
  JWT_SECRET_KEY=$("$PYTHON" -c "import secrets; print(secrets.token_hex(32))")
  cat > .env << EOF
SECRET_KEY=$SECRET_KEY
JWT_SECRET_KEY=$JWT_SECRET_KEY
DATABASE_URL=sqlite:///audinexia.db
FLASK_ENV=development
EOF
else
  echo "-- .env already exists, leaving it as-is"
fi

echo "-- Applying database migrations"
FLASK_APP=app.py "$PYTHON" -m flask db upgrade

echo ""
echo "Setup complete. To start the server:"
echo "  cd backend"
echo "  $ACTIVATE_HINT"
echo "  python app.py"
echo ""
echo "Then open http://127.0.0.1:5000/login"
