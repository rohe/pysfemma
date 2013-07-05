set femmadir=c:\pysfemma
set pythonbin=c:\python2.7.5\python.exe
set fedmetadata=http://md.swamid.se/md/swamid-2.0.xml
set certificate=swamid.crt
set powershell=c:\windows\system32\windowspowershell\v1.0\powershell.exe
set pshscript=.\update_adfs_rptrust.ps1

cd %femmadir%
%pythonbin% pysfemma.py -u %fedmetadata% -c %certificate%
%powershell% -ExecutionPolicy Unrestricted -File %pshscript%
%pythonbin% pysfemma.py -c
