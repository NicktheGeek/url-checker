@echo off
REM Builds a Desktop shortcut that launches URL Checker as its own window
REM (no console, taskbar icon) -- wraps this same project, same .venv,
REM same history.db/.env as start.bat/python app.py.
REM
REM Requires the Microsoft Edge WebView2 Runtime, preinstalled on virtually
REM all current Windows 10/11 machines (pywebview's Windows backend needs it).
REM
REM Best-effort: written and documented, but not run/verified on Windows --
REM this project was built and tested on macOS. If something doesn't work,
REM check the plain error output from running this .bat directly.
setlocal
cd /d "%~dp0"
set ROOT=%cd%

echo Setting up .venv + dependencies ...
python start.py --setup-only
if errorlevel 1 exit /b 1

echo Building app icon ...
"%ROOT%\.venv\Scripts\python.exe" -m pip install -q pillow
"%ROOT%\.venv\Scripts\python.exe" "%ROOT%\installer\windows\make_ico.py"

echo Creating Desktop shortcut ...
powershell -NoProfile -Command ^
  "$s = (New-Object -ComObject WScript.Shell).CreateShortcut(\"$env:USERPROFILE\Desktop\URL Checker.lnk\");" ^
  "$s.TargetPath = '%ROOT%\.venv\Scripts\pythonw.exe';" ^
  "$s.Arguments = '\"%ROOT%\desktop_app.py\"';" ^
  "$s.WorkingDirectory = '%ROOT%';" ^
  "$s.IconLocation = '%ROOT%\static\icons\app.ico';" ^
  "$s.Save()"

echo.
echo Created: %USERPROFILE%\Desktop\URL Checker.lnk
echo Double-click it to launch. Logs (if anything goes wrong):
echo   %%LOCALAPPDATA%%\URL Checker\log.txt
