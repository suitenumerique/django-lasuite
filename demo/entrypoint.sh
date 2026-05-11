#!/bin/sh
set -e

# Run migrations on every startup so the DB is ready
python manage.py migrate --noinput

# Execute the passed command (default: runserver)
exec python manage.py "$@"
