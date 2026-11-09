@echo off
rem UltraViolet launcher - purple-team CLI session recorder
rem Starts UltraViolet.ps1 from this folder and forwards any arguments (e.g. -DataRoot, -NoTheme).
powershell.exe -ExecutionPolicy Bypass -File "%~dp0UltraViolet.ps1" %*
