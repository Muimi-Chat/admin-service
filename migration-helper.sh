#!/bin/bash

# Connect to the Django container
docker compose exec -T admin-api /bin/bash << EOF

# Navigate to the Django project directory
cd /app/src

# Perform migration
python manage.py makemigrations adminapi
python manage.py migrate

# Show migrations
python manage.py showmigrations

# Check for errors during migration
python manage.py check --deploy

EOF
