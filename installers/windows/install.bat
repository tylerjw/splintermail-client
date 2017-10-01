:::::: Unpriviledged commands

@echo off
setlocal enabledelayedexpansion


::::::: dont do anything if GPG is not installed
echo Verifying GPG is installed...
gpg --version > NUL 2>&1
if %errorlevel% == 0 goto has_gpg
echo ERROR: DITM requires you to first install GPG.
echo Please visit www.gpg4win.org and click "download"
echo After installing, generate a GPG key pair and retry this installation.
pause
exit /B 1
:has_gpg
echo ...yes



set scriptdir=%cd%
cd ..\..
set rootdir=%cd%
set installdir=%rootdir%\install
set winSysFolder=System32

::::::: create install directory if needed
if not exist "%installdir%" mkdir "%installdir%"

::::::: if ditm directory already exists, delete any existing lock files
if exist "%installdir%\ditm" del "%installdir%\ditm\*.lock" > NUL 2>&1

::::::: the rest of the install should be from the install directory
cd "%installdir%"

::::::: Check if we already have python3 installed
echo Checking if python3 is already installed
set pythoncmd=
for /F %%G in ('where python 2^> NUL') do (
    for /F "delims=" %%H in ('%%G --version 2^>^&1') do set version=%%H
    if [!pythoncmd!] == [] if "!version:~7,1!" == "3" set pythoncmd=%%G
)
if not [!pythoncmd!] == [] goto skip_winpython
echo ...no, we will do a portable python3 installation

::::::: get latest version of winpython that splintermail is hosting
echo Asking splintermail.com which version of WinPython we need
set url=https://splintermail.com/downloads/latest_winpython.txt
set pcmd=(new-object System.Net.WebClient).DownloadFile(\"%url%\",\"latest_winpython.txt\")
powershell %pcmd%


::::::: parse version from latest_winpython.txt
set /p winpyver=< latest_winpython.txt
set pyver=%winpyver:~0,-2%

set dest=WinPython-32bit-%winpyver%Zero.exe
if exist "%installdir%\%dest%" goto skip_downloading_winpython
::::::: download winpython from splintermail
echo Downloading WinPython, about 30 MB...
set url=https://splintermail.com/downloads/WinPython-32bit-%winpyver%Zero.exe
set pcmd=(new-object System.Net.WebClient).DownloadFile(\"%url%\",\"%dest%\")
powershell %pcmd%
echo DONE!!!

goto done_downloading_winpython
:skip_downloading_winpython
echo looks like WinPython is already downloaded, skipping download.
:done_downloading_winpython

if exist "%installdir%\WinPython-32bit-%winpyver%Zero" goto skip_installing_winpython
::::::: winpython explanation
echo ------------------------------
echo Now we will unpack a local copy of Python from WinPython
echo You will have to click through the installer,
echo but don't change any options.
echo ------------------------------

::::::: install winpython
start /wait %dest%
if %errorlevel% == 0 goto winpython_installed
echo ERROR: Winpython install failed.
pause
exit /B 1
:winpython_installed


goto done_installing_winpython
:skip_installing_winpython
echo looks like WinPython is already installed, skipping install.
:done_installing_winpython
set pythoncmd=%installdir%\WinPython-32bit-%winpyver%Zero\python-%pyver%\python.exe

goto done_winpython
:skip_winpython
echo found python, skipping WinPython download and installation
:done_winpython

::::::: test python command
echo verifying that python can be called as:
echo.    "!pythoncmd!"
"!pythoncmd!" --version > NUL 2>&1
if %errorlevel% == 0 goto python_works
echo ------------------------------
echo ERROR: if you got a "missing dll" message" try installing the
echo Visual C++ Redistributable for Visual Studio 2015 from the following URL:
echo.
echo.    https://www.microsoft.com/en-us/download/details.aspx?id=48145
echo.
echo Then rerun this batch script and this installation will continue.
echo.
echo installation failed, exiting...
echo ------------------------------
pause
exit /B 2
:python_works
echo ...python works.

if exist "nssm.exe" goto skip_downloading_nssm
::::::: get nssm.exe from the Non Sucking Service Manager
"!pythoncmd!" "%scriptdir%\get_nssm.py"
goto done_downloading_nssm
:skip_downloading_nssm
echo looks like nssm.exe is already downloaded, skipping download.
:done_downloading_nssm

::::::: generate splintermail.bat
echo @echo off > splintermail.bat
echo "!pythoncmd!" "%rootdir%\splintermail" --config "%installdir%\splintermail.gpg" %%* >> splintermail.bat

:::::::::: install ditm.py as a service
:::::::::: well first, write nssm_install.bat script to be called with elevated privileges
echo @echo off > nssm_install.bat
echo echo trying to stop any previously installed DITM service >> nssm_install.bat
echo "%cd%\nssm.exe" stop "DITM Service" >> nssm_install.bat
echo echo trying to remove any previously installed DITM service >> nssm_install.bat
echo "%cd%\nssm.exe" remove "DITM Service" confirm >> nssm_install.bat
echo echo installing new DITM service >> nssm_install.bat
echo "%cd%\nssm.exe" install "DITM Service" "!pythoncmd!" \"%rootdir%\ditm.py\" -m \"%installdir%\ditm\" -g \"%appdata%\gnupg\" >> nssm_install.bat
echo echo starting DITM service >> nssm_install.bat
echo "%cd%\nssm.exe" start "DITM Service" >> nssm_install.bat
echo echo DITM Service should be installed now >> nssm_install.bat
echo copy "%installdir%\splintermail.bat" "%SystemRoot%\%winSysFolder%" >> nssm_install.bat
echo echo splintermail script copied to PATH >> nssm_install.bat
echo pause >> nssm_install.bat
::echo del "%cd%\nssm_install.bat" >> nssm_install.bat


:::::::::: now write and invoke VBS script to call nssm_install.bat as admin
echo Installing the DITM service and copying splintermail program to PATH,
echo this needs elevated privileges.
set vbsGetPrivileges=install_ditm_service.vbs
echo Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
echo args = "/c """ + "%cd%\nssm_install.bat" + """ " >> "%vbsGetPrivileges%"
echo UAC.ShellExecute "%SystemRoot%\%winSysFolder%\cmd.exe", args, "", "runas", 1 >> "%vbsGetPrivileges%"
:: invoke the VBS script
start /wait "%SystemRoot%\%winSysFolder%\WScript.exe" "%vbsGetPrivileges%"
:: delete temp file
del "%vbsGetPrivileges%"


echo ALL DONE!
pause
cd "%scriptdir%"
setlocal disabledelayedexpansion
