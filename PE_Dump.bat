cls
@echo -------------[ PE_Dump.Compile.start ]-------------
del PE_Dump.exe
@\masm32\bin\ml /c /Zf /coff PE_Dump.asm
@echo --------------------------------------------------
\masm32\bin\Link /SUBSYSTEM:CONSOLE PE_Dump.obj
@del PE_Dump.obj
@echo -------------[ PE_Dump.Compile.end ]-------------

PE_Dump.exe 00.exe
