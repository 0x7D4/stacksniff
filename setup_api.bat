@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo   stacksniff API Localhost Setup Utility
echo ===================================================
echo.

:: 1. Check if uv is installed
where uv >nul 2>&1
if errorlevel 1 (
    echo [ERROR] 'uv' package manager not found. Please install it first.
    exit /b 1
)

:: 2. Check if Docker is running
echo [*] Checking Docker Desktop status...
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Desktop is not running or not installed.
    echo         Please start Docker Desktop and run this script again.
    exit /b 1
)
echo [OK] Docker is running.
echo.

:: 3. Start Redis container
echo [*] Starting Redis container (stacksniff-redis)...
docker start stacksniff-redis >nul 2>&1
if errorlevel 1 (
    docker run -d --name stacksniff-redis -p 6379:6379 redis >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Failed to start Redis container. check if port 6379 is already in use.
        exit /b 1
    )
)
echo [OK] Redis is running on port 6379.
echo.

:: 4. Setup Core stacksniff
echo [*] Installing dependencies and building technology signatures...
call uv sync
call uv run stacksniff update-fingerprints
echo [OK] Core library and signatures ready.
echo.

:: 5. Setup Django API Database and Token
echo [*] Applying migrations and setting up local auth credentials...
cd stacksniff-api
call uv run python manage.py migrate

:: Programmatically create/retrieve admin superuser and generate DRF Token
call uv run python -c "import os, django; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.dev'); django.setup(); from django.contrib.auth.models import User; from rest_framework.authtoken.models import Token; u, c = User.objects.get_or_create(username='admin'); (u.set_password('adminpass'), print('[INFO] Created default user: admin / adminpass')) if c else None; u.is_superuser=True; u.is_staff=True; u.save(); t, _ = Token.objects.get_or_create(user=u); print('AUTH_TOKEN_KEY:' + t.key)" > temp_token.txt

:: Extract token key from output
set TOKEN_KEY=
for /f "tokens=2 delims=:" %%a in ('findstr "AUTH_TOKEN_KEY" temp_token.txt') do (
    set TOKEN_KEY=%%a
)
del temp_token.txt

if "%TOKEN_KEY%"=="" (
    echo [ERROR] Failed to generate authentication token.
    cd ..
    exit /b 1
)

echo [OK] Local database and authorization key prepared.
echo.

echo ===================================================
echo   Setup Complete! Your API details:
echo ===================================================
echo.
echo   API Base URL:  http://127.0.0.1:8000/api/
echo   Default User:  admin
echo   Auth Token:    %TOKEN_KEY%
echo.
echo ---------------------------------------------------
echo   To start the API service, open two terminals:
echo ---------------------------------------------------
echo.
echo   Terminal 1 (Django Server):
echo     cd stacksniff-api
echo     uv run uvicorn config.asgi:application --host 127.0.0.1 --port 8000 --reload
echo.
echo   Terminal 2 (Celery worker):
echo     cd stacksniff-api
echo     uv run celery -A config worker --pool=gevent --concurrency=10 --loglevel=info
echo.
echo ===================================================

cd ..
endlocal
