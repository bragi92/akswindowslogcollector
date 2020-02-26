FROM mcr.microsoft.com/windows/nanoserver:1909

ENV DEVKITFILENAME DevKit-mingw64-64-4.7.2-20130224-1432-sfx.exe
ENV APPDIR c:\\app
ENV DEVKITDIR devkit

RUN powershell -Command \
	$ErrorActionPreference = 'Stop'; \
	Invoke-WebRequest -Method Get -Uri http://dl.bintray.com/oneclick/rubyinstaller/rubyinstaller-2.3.3-x64.exe -OutFile c:\rubyinstaller-2.3.3-x64.exe; \
	Start-Process c:\rubyinstaller-2.3.3-x64.exe -ArgumentList '/verysilent' -Wait; \
	Remove-Item c:\rubyinstaller-2.3.3-x64.exe -Force;
RUN powershell -command "wget 'http://dl.bintray.com/oneclick/rubyinstaller/%DEVKITFILENAME%' -outfile %DEVKITFILENAME%";
RUN powershell -command $env:chocolateyUseWindowsCompression = 'false'; \
    "iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex";
RUN SET PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin;C:\Ruby23-x64\bin
RUN choco install 7zip -y
RUN powershell -command "& '%PROGRAMFILES%\\7-zip\\7z' e -r -y -o%DEVKITDIR% %DEVKITFILENAME%"
RUN powershell -command "cd %DEVKITDIR%; C:\\Ruby23-x64\\bin\\ruby dk.rb init"
RUN powershell -command "cd %DEVKITDIR%; add-content config.yml '- C:\\Ruby23-x64'"
RUN powershell -command "cd %DEVKITDIR%; C:\\Ruby23-x64\\bin\\ruby dk.rb install"

RUN mkdir %APPDIR%
WORKDIR /app

COPY Gemfile* /app/
RUN C:\Ruby23-x64\bin\gem install bundler --no-ri --no-rdoc
RUN C:\Ruby23-x64\bin\bundle install --without development test

COPY . /app