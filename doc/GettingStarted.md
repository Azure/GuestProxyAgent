# Getting Started with Windows

## Prerequisites

The following must be installed in order to build this project:

1. Git (e.g., [Git for Windows 64-bit](https://git-scm.com/download/win))
2. **Visual Studio 2022** - one of the following editions should be installed (once installed, upgrade to **v17.4.2 or later**):

   - [Download Visual Studio Community 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=17) (free)
   - [Download Visual Studio Professional 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Professional&rel=17)
   - [Download Visual Studio Enterprise 2022](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Enterprise&rel=17)

   during the installation, select the following feature from the *Visual Studio Installer*:

   - `"Desktop development with C++"`
   - `"The Windows 10 or 11 SDK"`

   including the following *Spectre* library, which must be selected from the "*Individual components*" tab in the Visual Studio Installer:

   - `"MSVC v143 - VS 2022 C++ x64/x86 Spectre-mitigated libs (latest)"`

3. [WDK for Windows 11, version 22H2](https://go.microsoft.com/fwlink/?linkid=2196230) (version **10.0.22621.x**), including the
 "*Windows Driver Kit Visual Studio extension*" (make sure the "*Install Windows Driver Kit Visual Studio Extension*"
  check box is checked before completing the installer).
    >Note: as multiple versions of WDKs cannot coexist side-by-side, you may be asked to uninstall previous versions.

4. [Clang for Windows 64-bit](https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.1/LLVM-11.0.1-win64.exe) (version **11.0.1**).
 Note: clang versions 12 and higher are NOT yet supported, as they perform program optimizations that are incompatible with the PREVAIL verifier.
5. [NuGet Windows x86 Commandline](https://www.nuget.org/downloads) (version **6.31 or higher**), which can be installed to a location such as "C:\Program Files (x86)\NuGet\".
6. [Installing rustup on Windows](https://www.rust-lang.org/tools/install), to start using Rust, download the installer, then run the program and follow the default onscreen instructions.

You should add the paths to `git.exe` and `nuget.exe` to the Windows PATH environment variable after the software packages
 above have been installed.

## How to clone and build the project
This section outlines the steps to build, prepare and build this project.

### Cloning the project
1. ```git clone https://github.com/Azure/GuestProxyAgent.git```.
By default this will clone the project under the `GuestProxyAgent` directory.

### Build the project
1. Launch `Developer Command Prompt for VS 2022` with administrators permission.
2. Navigate to this repo root folder.
2. ```build.cmd```

