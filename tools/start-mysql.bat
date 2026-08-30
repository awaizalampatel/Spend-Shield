@echo off
REM Starts MariaDB for SpendShield in its own window.
REM
REM Use this when the XAMPP Control Panel's Start button does nothing. The usual
REM cause is that something already holds port 3306 - this script checks first
REM and tells you, instead of failing silently the way the panel does.
REM
REM Leave the window open. Closing it stops the database.

setlocal
set MYSQL=C:\xampp\mysql\bin

echo Checking port 3306...
netstat -ano | findstr /R /C:":3306 .*LISTENING" >nul
if %errorlevel%==0 (
  echo.
  echo   Port 3306 is already in use - MySQL is probably already running.
  echo   If the app still cannot connect, shut the old one down first:
  echo.
  echo     "%MYSQL%\mysqladmin.exe" -u root shutdown
  echo.
  pause
  exit /b 1
)

echo Starting MariaDB. Keep this window open.
echo.
"%MYSQL%\mysqld.exe" --defaults-file="%MYSQL%\my.ini" --standalone --console

echo.
echo MariaDB has stopped.
pause
