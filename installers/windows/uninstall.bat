@echo off
set installdir=%cd%\..\..\install

::::::: check if install directory exists
if exist "%installdir%" goto has_installdir
echo the install directory does not seem to exist.
echo try re-installing and then uninstalling
pause
exit /B 1

:has_installdir
if exist "%installdir%/nssm.exe" goto has_nssm
echo install directory exists, but nssm.exe is missing
echo most likely the service is not installed...
echo but try re-installing and then uninstalling
pause
exit /B 2

:has_nssm

:::::::::: write the nssm uninstaller script
echo @echo off > nssm_uninstall.bat
echo echo trying to stop DITM service >> nssm_uninstall.bat
echo "%installdir%\nssm.exe" stop "DITM Service" >> nssm_uninstall.bat
echo echo trying to remove DITM service >> nssm_uninstall.bat 
echo "%installdir%\nssm.exe" remove "DITM Service" confirm >> nssm_uninstall.bat
echo echo DITM Service should be uninstalled now >> nssm_uninstall.bat
echo del "%SystemRoot%\%winSysFolder%\splintermail.bat" >> nssm_uninstall.bat
echo echo splintermail script deleted from PATH >> nssm_uninstall.bat
echo echo deleting splintermail install directory >> nssm_uninstall.bat
echo rmdir /S /Q "%installdir%" >> nssm_uninstall.bat
echo pause >> nssm_uninstall.bat
echo del "%cd%\nssm_uninstall.bat" >> nssm_uninstall.bat


:::::::::: now write and invoke VBS script to call nssm_uninstall.bat as admin
echo Installing the DITM service and deleting splintermail program from PATH,
echo this needs elevated privileges.
set winSysFolder=System32
set vbsGetPrivileges=install_ditm_service.vbs
echo Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
echo args = "/c """ + "%cd%\nssm_uninstall.bat" + """ " >> "%vbsGetPrivileges%"
echo UAC.ShellExecute "%SystemRoot%\%winSysFolder%\cmd.exe", args, "", "runas", 1 >> "%vbsGetPrivileges%"
:: invoke the VBS script
start /wait "%SystemRoot%\%winSysFolder%\WScript.exe" "%vbsGetPrivileges%"
:: delete temp file
del "%vbsGetPrivileges%"


echo ALL DONE!!!
pause
