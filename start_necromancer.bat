@echo off
setlocal

echo === Project Necromancer Setup & Launcher ===

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python and try again.
    pause
    exit /b
)

:: Install Python requirements
echo [INFO] Installing required Python packages...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install Python requirements.
    pause
    exit /b
)

:: Check for Ollama
ollama --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Ollama is not installed. 
    echo To use the AI Analyst features, please download and install Ollama from https://ollama.com
    echo The system will fall back to rule-based logic for now.
    echo Press any key to continue without AI, or close this window to install Ollama first.
    pause
) else (
    echo [INFO] Ollama detected. Ensuring phi3 model is downloaded...
    echo [INFO] (This may take a few minutes if downloading for the first time)
    ollama pull phi3
)

:: Start the backend engine in the background
echo [INFO] Starting the Project Necromancer engine...
start /B python main.py

:: Start the Streamlit Dashboard in the background with public flags
echo [INFO] Starting the Dashboard...
start /B streamlit run interface\dashboard.py --server.port 8501 --server.address 0.0.0.0 --server.enableCORS false --server.enableXsrfProtection false

:: Give Streamlit a moment to start up
timeout /t 3 /nobreak >nul

:: Start Cloudflare tunnel in the foreground so the user sees the public link
echo [INFO] Creating public tunnel...
cloudflared tunnel --url http://localhost:8501

echo === Exiting Launcher ===
endlocal
