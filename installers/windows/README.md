# What should I expect from the Windows install.bat batch script?

The Windows installation strives to be as portable as possible.  All installed files will exist in a subfolder of the `splintermail-client` folder, with the exception of a `splintermail.bat` file which is copied to your PATH.

Currently, install.bat is tested on clean installations of Windows 7 and Windows 10.

# What steps does install.bat do?

1. Check if GPG is installed, exit if not found
2. Check if python3 is installed, if not download a copy of the portable WinPython
3. Download the Non-Sucking Service Manager (a tiny standalone executable)
4. Request elevated privileges
5. Use nssm.exe to install DITM as a Windows startup for seamless startup and operation
6. Create a `splintermail.bat` script on the PATH for easy command-line use

# Troubleshooting

#### I got an error that says: `The program can't start because api-ms-win-crt-runtime-l1-1-0.dll is missing from your computer.`

This can happen using WinPython on Windows 7 if Windows Update is not enabled.  Just install [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145)

