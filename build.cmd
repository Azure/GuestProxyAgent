REM Copyright (c) Microsoft Corporation
REM SPDX-License-Identifier: MIT

@echo off
SET root_path=%~dp0
SET out_path=%root_path%out
set Configuration=%1
set CleanBuild=%2
set ContinueAtConvertBpfToNative=%3
if "%Configuration%"=="" (SET Configuration=debug)
echo Configuration=%Configuration%
echo out_path=%out_path%
SET out_dir=%out_path%\%Configuration%

SET eBPF_for_Windows_bin_path=%root_path%packages\eBPF-for-Windows.0.11.0\build\native\bin
SET eBPF_for_Windows_inc_path=%root_path%packages\eBPF-for-Windows.0.11.0\build\native\include
SET bin_skim_path=%root_path%packages\Microsoft.CodeAnalysis.BinSkim.1.9.5\tools\netcoreapp3.1\win-x64
SET rustup_version=1.69.0


if "%CleanBuild%"=="clean" (
    echo ======= delete old files
    echo RD /S /Q %out_dir%
    RD /S /Q %out_dir%

    echo RD /S /Q %root_path%packages
    RD /S /Q %root_path%packages
)

echo ======= nuget restore
call nuget restore
if  %ERRORLEVEL% NEQ 0 (
    echo call nuget restore with exit-code: %errorlevel%
    exit /b %errorlevel%
)

echo ======= rustup update to a particular version
call rustup update %rustup_version%

echo ======= create out path folder and subfolder
if not exist "%out_path%" (md "%out_path%")
if not exist "%out_dir%" (md "%out_dir%")

echo ======= Prepare out-package folder structure
SET out_package_dir=%out_dir%\package
if not exist "%out_package_dir%" (md "%out_package_dir%")
SET out_package_proxyagent_dir="%out_package_dir%"\ProxyAgent
if not exist "%out_package_proxyagent_dir%" (md "%out_package_proxyagent_dir%")

echo ======= copy VB Scripts to Package folder
xcopy /Y %root_path%\Setup\Windows\*.* %out_package_dir%\

echo ======= build ebpf program
SET ebpf_path=%root_path%\ebpf
echo call clang -target bpf -Werror -O2 -c %ebpf_path%\redirect.bpf.c -o %out_dir%\redirect.bpf.o
call clang -target bpf -Werror -O2 -c %ebpf_path%\redirect.bpf.c -o %out_dir%\redirect.bpf.o
if  %ERRORLEVEL% NEQ 0 (
    echo call clang failed with exit-code: %errorlevel%
    exit /b %errorlevel%
)
echo ======= copy redirect.bpf.o
xcopy /Y %out_dir%\redirect.bpf.o %out_package_proxyagent_dir%\
echo ======= convert redirect.bpf.o to redirect.bpf.sys
call %eBPF_for_Windows_bin_path%\export_program_info.exe --clear
call %eBPF_for_Windows_bin_path%\export_program_info.exe
echo call powershell.exe %eBPF_for_Windows_bin_path%\Convert-BpfToNative.ps1 -OutDir %out_dir% -FileName redirect.bpf.o -IncludeDir %eBPF_for_Windows_bin_path%
call powershell.exe %eBPF_for_Windows_bin_path%\Convert-BpfToNative.ps1 -OutDir %out_dir% -FileName redirect.bpf.o -IncludeDir %eBPF_for_Windows_inc_path%
if  %ERRORLEVEL% NEQ 0 (
    echo call Convert-BpfToNative.ps1 failed with exit-code: %errorlevel%
    if "%ContinueAtConvertBpfToNative%"=="" (
        exit /b %errorlevel%
    )
    echo Skip the error and continue to build other projects
)
echo ======= copy redirect.bpf.sys
xcopy /Y %out_dir%\redirect.bpf.sys %out_package_proxyagent_dir%\
xcopy /Y %out_dir%\redirect.bpf.pdb %out_package_proxyagent_dir%\

echo ======= build proxy_agent_shared
set cargo_toml=%root_path%proxy_agent_shared\Cargo.toml
SET release_flag=
if "%Configuration%"=="release" (SET release_flag=--release)
echo cargo_toml=%cargo_toml%
echo call cargo +%rustup_version% build %release_flag% --manifest-path %cargo_toml% --target-dir %out_path%
call cargo +%rustup_version% build %release_flag% --manifest-path %cargo_toml% --target-dir %out_path%
if  %ERRORLEVEL% NEQ 0 (
    echo call cargo build proxy_agent_shared failed with exit-code: %errorlevel%
    exit /b %errorlevel%
)

echo ======= copy files for run/debug proxy_agent_shared Unit test in VS Code
echo xcopy /Y /C /Q %out_dir% %out_dir%\deps\
xcopy /Y /C /Q %out_dir% %out_dir%\deps\
echo xcopy /Y /S /C /Q %out_dir% %root_path%proxy_agent_shared\target\%Configuration%\
xcopy /Y /S /C /Q %out_dir% %root_path%proxy_agent_shared\target\%Configuration%\

echo ======= run rust proxy_agent_shared tests
echo call cargo +%rustup_version% test  %release_flag% --manifest-path %cargo_toml% --target-dir %out_path% -- --test-threads=1
call cargo +%rustup_version% test  %release_flag% --manifest-path %cargo_toml% --target-dir %out_path% -- --test-threads=1
if  %ERRORLEVEL% NEQ 0 (
    echo call cargo test proxy_agent_shared with exit-code: %errorlevel%
    exit /b %errorlevel%
)

echo ======= copy config file for windows platform
echo ======= Adding a wildcard (*) to the end of the destination will suppress this prompt and default to copying as a file:
xcopy /Y %root_path%proxy_agent\config\GuestProxyAgent.windows.json %out_dir%\GuestProxyAgent.json*

echo ======= build proxy_agent
set cargo_toml=%root_path%proxy_agent\Cargo.toml
SET release_flag=
if "%Configuration%"=="release" (SET release_flag=--release)
echo cargo_toml=%cargo_toml%
echo call cargo +%rustup_version% build %release_flag% --manifest-path %cargo_toml% --target-dir %out_path%
call cargo +%rustup_version% build %release_flag% --manifest-path %cargo_toml% --target-dir %out_path%
if  %ERRORLEVEL% NEQ 0 (
    echo call cargo build proxy_agent failed with exit-code: %errorlevel%
    exit /b %errorlevel%
)

echo ======= copy files for run/debug proxy_agent Unit test
echo xcopy /Y /C /Q %eBPF_for_Windows_bin_path%\EbpfApi.* %out_dir%\
xcopy /Y /C /Q %eBPF_for_Windows_bin_path%\EbpfApi.* %out_dir%\
echo xcopy /Y /C /Q %out_dir% %out_dir%\deps\
xcopy /Y /C /Q %out_dir% %out_dir%\deps\
echo xcopy /Y /S /C /Q %out_dir% %root_path%proxy_agent\target\%Configuration%\
xcopy /Y /S /C /Q %out_dir% %root_path%proxy_agent\target\%Configuration%\

echo ======= run rust proxy_agent tests
echo call cargo +%rustup_version% test  %release_flag% --manifest-path %cargo_toml% --target-dir %out_path% -- --test-threads=1
call cargo +%rustup_version% test  %release_flag% --manifest-path %cargo_toml% --target-dir %out_path% -- --test-threads=1
if  %ERRORLEVEL% NEQ 0 (
    echo call cargo test proxy_agent with exit-code: %errorlevel%
    exit /b %errorlevel%
)

echo ======= build proxy_agent_extension
SET extension_root_path=%root_path%proxy_agent_extension
SET extension_src_path=%root_path%proxy_agent_extension\src\windows
set cargo_toml=%extension_root_path%\Cargo.toml
echo cargo_toml=%cargo_toml%
echo call cargo +%rustup_version% build %release_flag% --manifest-path %cargo_toml% --target-dir %out_path%
call cargo +%rustup_version% build %release_flag% --manifest-path %cargo_toml% --target-dir %out_path%
if  %ERRORLEVEL% NEQ 0 (
    echo call cargo build proxy_agent_extension failed with exit-code: %errorlevel%
    exit /b %errorlevel%
)

echo ======= copy files for run/debug proxy_agent_extension Unit test
echo xcopy /Y /C /Q %out_dir% %out_dir%\deps\
xcopy /Y /C /Q %out_dir% %out_dir%\deps\
echo xcopy /Y /S /C /Q %out_dir% %root_path%proxy_agent_extension\target\%Configuration%\
xcopy /Y /S /C /Q %out_dir% %root_path%proxy_agent_extension\target\%Configuration%\

echo ======= run rust proxy_agent_extension tests
echo call cargo +%rustup_version% test  %release_flag% --manifest-path %cargo_toml% --target-dir %out_path% -- --test-threads=1
call cargo +%rustup_version% test  %release_flag% --manifest-path %cargo_toml% --target-dir %out_path% -- --test-threads=1
if  %ERRORLEVEL% NEQ 0 (
    echo call cargo test proxy_agent_extension with exit-code: %errorlevel%
    exit /b %errorlevel%
)

echo ======= build proxy_agent_setup
set cargo_toml=%root_path%proxy_agent_setup\Cargo.toml
SET release_flag=
if "%Configuration%"=="release" (SET release_flag=--release)
echo cargo_toml=%cargo_toml%
echo call cargo +%rustup_version% build %release_flag% --manifest-path %cargo_toml% --target-dir %out_path%
call cargo +%rustup_version% build %release_flag% --manifest-path %cargo_toml% --target-dir %out_path%
if  %ERRORLEVEL% NEQ 0 (
    echo call cargo build proxy_agent_setup failed with exit-code: %errorlevel%
    exit /b %errorlevel%
)

echo ======= restore e2e test project dependencies
echo call dotnet.exe restore %root_path%\e2etest\GuestProxyAgentTest.sln
call dotnet.exe restore %root_path%\e2etest\GuestProxyAgentTest.sln
if  %ERRORLEVEL% NEQ 0 (
    echo call dotnet.exe restore failed with exit-code: %errorlevel%
    exit /b %errorlevel%
)

echo ======= build e2e test project
SET out_e2etest_dir=%out_dir%\e2etest
echo call dotnet.exe build %root_path%\e2etest\GuestProxyAgentTest.sln --no-restore --configuration %Configuration% -o %out_e2etest_dir%
call dotnet.exe build %root_path%\e2etest\GuestProxyAgentTest.sln --no-restore --configuration %Configuration% -o %out_e2etest_dir%
if  %ERRORLEVEL% NEQ 0 (
    echo call dotnet.exe build failed with exit-code: %errorlevel%
    exit /b %errorlevel%
)
dir /S /B %out_e2etest_dir%\

echo ======= copy setup tool to Package folder
xcopy /Y %out_dir%\proxy_agent_setup.exe %out_package_dir%\
xcopy /Y %out_dir%\proxy_agent_setup.pdb %out_package_dir%\

echo ======= copy to ProxyAgent folder
xcopy /Y %out_dir%\GuestProxyAgent.exe %out_package_proxyagent_dir%\
xcopy /Y %out_dir%\GuestProxyAgent.pdb %out_package_proxyagent_dir%\
xcopy /Y %out_dir%\GuestProxyAgent.json %out_package_proxyagent_dir%\
xcopy /Y %out_dir%\EbpfApi.dll %out_package_proxyagent_dir%\
xcopy /Y %out_dir%\EbpfApi.pdb %out_package_proxyagent_dir%\

SET out_package_proxyagent_extension_dir=%out_package_dir%\ProxyAgent_Extension
if not exist "%out_package_proxyagent_extension_dir%" (md "%out_package_proxyagent_extension_dir%")
echo ======= copy ProxyAgent Extension files
xcopy /Y %extension_src_path%\HandlerManifest.json %out_package_proxyagent_extension_dir%\
for %%F in (%extension_src_path%\*.cmd) do (
    echo Found file: %%F
    xcopy /Y %%F %out_package_proxyagent_extension_dir%\
)
xcopy /Y %out_dir%\ProxyAgentExt.exe %out_package_proxyagent_extension_dir%\

echo ======= copy e2e test project to Package folder
SET out_package_e2etest_dir=%out_package_dir%\e2etest
echo xcopy /Y /S /C /Q %out_e2etest_dir% %out_package_e2etest_dir%\
xcopy /Y /S /C /Q %out_e2etest_dir% %out_package_e2etest_dir%\

echo ======= run binskim command
call %bin_skim_path%\BinSkim.exe analyze %out_package_proxyagent_dir%\GuestProxyAgent.exe --output %out_package_proxyagent_dir%\GuestProxyAgent.exe.binskim.json --rich-return-code=true --force

echo ======= Generate build-configuration.zip file
call powershell.exe Compress-Archive -Path "%out_package_dir%" -DestinationPath "%out_dir%"\build-%Configuration%-windows-amd64.zip" -Force