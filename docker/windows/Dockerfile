FROM mcr.microsoft.com/windows/server:ltsc2022
WORKDIR C:/Users/ContainerAdministrator

ARG RUST_VERSION

RUN curl -SL --output vs_community.exe https://aka.ms/vs/17/release/vs_community.exe

# Install VS Build Tools with:
#   Desktop development with C++ (w/recommended)
#   MSVC v143 - VS 2022 C++ ARM64/ARM64EC Spectre-mitigated libs (Latest)
#   MSVC v143 - VS 2022 C++ x64/x86 Spectre-mitigated libs (Latest)
#   C++ ATL for latest v143 build tools with Spectre Mitigations (ARM64/ARM64EC)
#   C++ ATL for latest v143 build tools with Spectre Mitigations (x86 & x64)
#   C++ MFC for latest v143 build tools with Spectre Mitigations (ARM64/ARM64EC)
#   C++ MFC for latest v143 build tools with Spectre Mitigations (x86 & x64)
#   Windows Driver Kit
#   Windows 11 SDK (10.0.26100.0)
RUN start /w vs_community.exe --quiet --wait --norestart --nocache \
    --installPath "%ProgramFiles%\Microsoft Visual Studio\2022\Community" \
    --includeRecommended \
    --add Microsoft.VisualStudio.Workload.NativeDesktop \
    --add Microsoft.VisualStudio.Component.VC.Runtimes.ARM64.Spectre \
    --add Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre \
    --add Microsoft.VisualStudio.Component.VC.ATL.ARM64.Spectre \
    --add Microsoft.VisualStudio.Component.VC.ATL.Spectre \
    --add Microsoft.VisualStudio.Component.VC.MFC.ARM64.Spectre \
    --add Microsoft.VisualStudio.Component.VC.ATLMFC.Spectre \
    --add Component.Microsoft.Windows.DriverKit \
    --add Microsoft.VisualStudio.Component.Windows11SDK.26100 \
    || IF "%ERRORLEVEL%"=="3010" EXIT 0

# WDK for Windows 11, version 10.0.26100.1)
RUN curl -SL --output wdksetup.exe https://go.microsoft.com/fwlink/?linkid=2272234
RUN wdksetup.exe /quiet /norestart /log wdksetup.log
RUN SET "PATH=C:\Program Files (x86)\Windows Kits\10\bin\x64\;%PATH%"

# Install Chocolatey
RUN powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; \
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; \
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"

# Install Clang
RUN choco install -y llvm --version 11.0.1 --allow-downgrade

RUN choco install nuget.commandline -y
RUN choco install dotnet-sdk -y
RUN choco install git -y

# Rust
RUN curl -SL --output rustup-init.exe https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe
RUN rustup-init.exe -y -q
RUN SET "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
RUN rustup update %RUST_VERSION%
RUN rustup default %RUST_VERSION%

ENTRYPOINT ["C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\Tools\\VsDevCmd.bat", \
    "&&", "powershell.exe", "-NoLogo", "-ExecutionPolicy", "Bypass"]
