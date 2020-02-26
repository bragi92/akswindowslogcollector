# escape=`

ARG WINDOWS_VERSION=1909

#
# Builder Image - Windows Server Core
# Assemble the components required to run Fluent Bit
#
FROM mcr.microsoft.com/windows/servercore:$WINDOWS_VERSION as builder

ARG FLUENTBIT_URL=https://ci.appveyor.com/api/buildjobs/37lho3xf8j5i6crj/artifacts/build%2Ftd-agent-bit-1.4.0-win64.zip

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

RUN Write-Host ('Creating folders'); `
    New-Item -Type Directory -Path /installation; `
    New-Item -Type Directory -Path /fluent-bit;

WORKDIR /installation

RUN Write-Host ('Installing Fluent Bit'); `
    Invoke-WebRequest -Uri $Env:FLUENTBIT_URL -OutFile /installation/td-agent-bit.zip; `
    Expand-Archive -Path /installation/td-agent-bit.zip -Destination /installation/fluent-bit; `
    Move-Item -Path /installation/fluent-bit/*/* -Destination /fluent-bit/;

#
# Technique from https://github.com/StefanScherer/dockerfiles-windows/blob/master/mongo/3.6/Dockerfile
# 
RUN Write-Host ('Installing Visual C++ Redistributable Package'); `
    $ProgressPreference = 'SilentlyContinue'; `
    Invoke-WebRequest -Uri 'https://aka.ms/vs/16/release/vc_redist.x64.exe' -OutFile /installation/vc_redist.x64.exe; `
    $ProgressPreference = 'Continue'; `
    Start-Process /installation/vc_redist.x64.exe -ArgumentList '/install', '/quiet', '/norestart' -NoNewWindow -Wait; `
    Copy-Item -Path /Windows/System32/msvcp140.dll -Destination /fluent-bit/bin; `
    Copy-Item -Path /Windows/System32/vccorlib140.dll -Destination /fluent-bit/bin; `
    Copy-Item -Path /Windows/System32/vcruntime140.dll -Destination /fluent-bit/bin;

#
# Runtime Image - Windows Server Nano
# Run Fluent Bit with appropriate configuration 
#
FROM mcr.microsoft.com/windows/nanoserver:$WINDOWS_VERSION as runtime

COPY --from=builder /fluent-bit /fluent-bit

ENTRYPOINT ["c:\\fluent-bit\\bin\\fluent-bit.exe", "-i", "dummy", "-o", "stdout"]
