#!/bin/sh
PYTHONDONTWRITEBYTECODE=1
gunicorn --workers 4 --threads 4 --bind 0.0.0.0:8000 --chdir /app main:app