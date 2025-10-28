@echo off

    if exist "test.obj" del "test.obj"
    if exist "test.exe" del "test.exe"

    \masm32\bin\ml /c /coff "test.asm"
    if errorlevel 1 goto errasm

    \masm32\bin\PoLink /SUBSYSTEM:CONSOLE "test.obj"
    if errorlevel 1 goto errlink
    dir "test.*"
    goto TheEnd

  :errlink
    echo _
    echo Link error
    goto TheEnd

  :errasm
    echo _
    echo Assembly Error
    goto TheEnd
    
  :TheEnd

pause
