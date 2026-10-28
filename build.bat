@echo off
setlocal
cd /d "%~dp0"
echo === Construction de AntiDDoS.exe ===
where py >nul 2>nul
if errorlevel 1 (
  echo Python n'est pas installe. Installe Python 3.12 depuis python.org
  echo ^(coche "Add python.exe to PATH"^), puis relance ce fichier.
  pause
  exit /b 1
)
py -m pip install --upgrade pip
py -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto fail
if not exist site_url.txt type nul > site_url.txt
py -m PyInstaller --noconfirm --clean --onefile --noconsole --uac-admin --name AntiDDoS --icon icon.ico --add-data "dashboard.html;." --add-data "site_url.txt;." antiddos_win.py
if errorlevel 1 goto fail
echo.
echo Termine : dist\AntiDDoS.exe
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist "%ISCC%" (
  "%ISCC%" installer.iss
  if errorlevel 1 goto fail
  echo Installateur : installer_output\AntiDDoS-Setup.exe
) else (
  echo ^(Pour aussi creer l'installateur, installe Inno Setup 6 : jrsoftware.org/isinfo.php^)
)
pause
exit /b 0
:fail
echo.
echo Erreur pendant la construction. Copie le message ci-dessus pour demander de l'aide.
pause
exit /b 1
