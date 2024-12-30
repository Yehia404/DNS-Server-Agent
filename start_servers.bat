@echo off

REM Start the Recursive Resolver
start "Recursive Resolver" cmd /k "python recursive_resolver.py"

REM Start the Root Server
start "Root Server" cmd /k "python root_server.py"

REM Start TLD Servers
start "TLD Server - com" cmd /k "python tld_server.py tld_table.json com"
start "TLD Server - org" cmd /k "python tld_server.py tld_table.json org"
start "TLD Server - arpa" cmd /k "python tld_server.py tld_table.json arpa"

REM Start Authoritative Servers
start "Auth Server - google" cmd /k "python auth_server.py auth_table.json google"
start "Auth Server - microsoft" cmd /k "python auth_server.py auth_table.json microsoft"
start "Auth Server - wikipedia" cmd /k "python auth_server.py auth_table.json wikipedia"
start "Auth Server - arpa" cmd /k "python auth_server.py auth_table.json arpa"