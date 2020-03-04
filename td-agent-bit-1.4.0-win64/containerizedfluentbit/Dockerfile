# escape=`

ARG WINDOWS_VERSION=1809

#
# Builder Image - Windows Server Core
# Assemble the components required to run Fluent Bit
#
FROM mcr.microsoft.com/windows/servercore:$WINDOWS_VERSION as builder

#
################# Dangerous to use appveyor links - the builds are removed after 6 months
#
#ARG FLUENTBIT_URL=https://ci.appveyor.com/api/buildjobs/37lho3xf8j5i6crj/artifacts/build%2Ftd-agent-bit-1.4.0-win64.zip
ARG FLUENTBIT_URL=https://github.com/bragi92/windowslog/raw/master/td-agent-bit-1.4.0-win64.zip

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

# Script to run fluent bit in the background
RUN New-Item -Type Directory -Path /omsagentwindows
WORKDIR /omsagentwindows
COPY .\backgroundrunner.ps1 'C:\\omsagentwindows\\'
COPY .\fluent-bit.conf 'C:\\omsagentwindows\\'
COPY .\oms.crt 'C:\\omsagentwindows\\'
COPY .\oms.key 'C:\\omsagentwindows\\'
COPY .\out_oms.so 'C:\\omsagentwindows\\'
COPY .\parsers.conf 'C:\\omsagentwindows\\'
COPY .\plugins.conf 'C:\\omsagentwindows\\'
COPY .\certgenerator 'C:\\omsagentwindows\\'

#
# Ruby installer in the temporary windowsservercore image
#
ENV RUBY_VERSION 2.2.4
ENV DEVKIT_VERSION 4.7.2
ENV DEVKIT_BUILD 20130224-1432

#
# Runtime Image - Windows Server Nano
# Run Fluent Bit with appropriate configuration 
#
# FROM mcr.microsoft.com/powershell:windowsservercore-$WINDOWS_VERSION as runtime
FROM mcr.microsoft.com/windows/servercore:$WINDOWS_VERSION as runtime

COPY --from=builder /fluent-bit /fluent-bit
COPY --from=builder /omsagentwindows /omsagentwindows

#ENTRYPOINT ["powershell"]

ENTRYPOINT ["powershell", "c:\\omsagentwindows\\backgroundrunner.ps1"]
