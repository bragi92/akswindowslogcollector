$ErrorActionPreference = "SilentlyContinue"

kill -force -processname 'Docker for Windows', com.docker.db, com.docker.slirp, com.docker.proxy, com.docker.9pdb, moby-diag-dl, dockerd
kill -force -processname com.docker.service

try {
pushd "C:\Program Files\Docker\Docker\Resources"
./MobyLinux.ps1 -Destroy
popd
} Catch {}

$service = Get-WmiObject -Class Win32_Service -Filter "Name='com.docker.service'"
if ($service) { $service.StopService() }
if ($service) { $service.Delete() }
Start-Sleep -s 5
Remove-Item -Recurse -Force "~/AppData/Local/Docker"
Remove-Item -Recurse -Force "~/AppData/Roaming/Docker"
if (Test-Path "C:\ProgramData\Docker") { takeown.exe /F "C:\ProgramData\Docker" /R /A /D Y }
if (Test-Path "C:\ProgramData\Docker") { icacls "C:\ProgramData\Docker" /T /C /grant Administrators:F }
Remove-Item -Recurse -Force "C:\ProgramData\Docker"
Remove-Item -Recurse -Force "C:\Program Files\Docker"
Remove-Item -Recurse -Force "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Docker"
Remove-Item -Force "C:\Users\Public\Desktop\Docker for Windows.lnk"
Remove-Item -Recurse -Force "~.docker"
Remove-Item -Recurse -Force "~\DockerSwarm"
Get-ChildItem HKLM:\software\microsoft\windows\currentversion\uninstall | ForEach-Object {Get-ItemProperty $_.PSPath} | Where-Object { $_.DisplayName -eq "Docker" } | Remove-Item -Recurse -Force
Get-ChildItem HKLM:\software\classes\installer\products | ForEach-Object {Get-ItemProperty $_.pspath} | Where-Object { $_.ProductName -eq "Docker" } | Remove-Item -Recurse -Force
Get-Item 'HKLM:\software\Docker Inc.' | Remove-Item -Recurse -Force

Get-ItemProperty HKCU:\software\microsoft\windows\currentversion\Run -name "Docker for Windows" | Remove-Item -Recurse -Force
Get-ItemProperty HKCU:\software\microsoft\windows\currentversion\UFH\SHC | ForEach-Object {Get-ItemProperty $_.PSPath} | Where-Object { $_.ToString().Contains("Docker for Windows.exe") } | Remove-Item -Recurse -Force

Get-Item Env:\COMPOSE_CONVERT_WINDOWS_PATHS | Remove-Item
Get-Item Env:\DOCKER_* | Remove-Item # DOCKER_CERT_PATH, DOCKER_HOST, DOCKER_MACHINE_NAME, DOCKER_TLS_VERIFY