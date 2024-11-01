@echo off
color 03
Title Qu4ckUltra [MAIN.bat]

:: Define vars
set "windows=%windir%"
set "systemdrive=%systemdrive%"
set "userprofile=%userprofile%"
set "temp=%temp%"
set "history=%userprofile%\Local Settings\History"
set "cookies=%userprofile%\Cookies"
set "recent=%userprofile%\Recent"
set "printers=%systemroot%\system32\spool\printers"

:: Clean TEMP files
echo {Qu4ckUltra} [MAIN.bat]: Cleaning TEMP Files...
del /s /f /q "%windows%\temp\*.*" 2>nul
del /s /f /q "%windows%\Prefetch\*.exe" 2>nul
del /s /f /q "%windows%\Prefetch\*.dll" 2>nul
del /s /f /q "%windows%\Prefetch\*.pf" 2>nul
del /s /f /q "%windows%\system32\dllcache\*.*" 2>nul
del /s /f /q "%systemdrive%\Temp\*.*" 2>nul
del /s /f /q "%temp%\*.*" 2>nul
del /s /f /q "%history%\*.*" 2>nul
del /s /f /q "%userprofile%\Local Settings\Temporary Internet Files\*.*" 2>nul
del /s /f /q "%userprofile%\Local Settings\Temp\*.*" 2>nul
del /s /f /q "%recent%\*.*" 2>nul
del /s /f /q "%cookies%\*.*" 2>nul
echo {Qu4ckUltra} [MAIN.bat]: Finished cleaning!

:: Clean event reg
echo {Qu4ckUltra} [MAIN.bat]: Cleaning TEMP Files...
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")

:do_clear
echo {Qu4ckUltra} [MAIN.bat]: Cleaning %1...
wevtutil.exe cl %1
goto end

:noAdmin
echo {Qu4ckUltra} [MAIN.bat]: [!]: Execute as Admin!
goto end

:end
echo.
pause
echo {Qu4ckUltra} [MAIN.bat]: Finished! <press any key to close>
pause >nul

exit
