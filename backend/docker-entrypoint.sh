#!/bin/sh
set -e

echo "Applying database migrations..."
node dist/scripts/migrate.js

echo "Starting backend..."
exec node dist/src/server.js
