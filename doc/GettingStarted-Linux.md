# Getting Started

## Prerequisites

The following must be installed in order to build this project:

1. Rust ([Install Rust](https://www.rust-lang.org/tools/install)), follow the steps prompted during the installation.
   ```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ``` 

2. Install required packages for programming
   ```
   sudo apt update
   sudo apt install linux-headers-$(uname -r) \
           libbpfcc-dev \
           libbpf-dev \
           llvm \
           clang \
           gcc-multilib \
           build-essential \
           linux-tools-$(uname -r) \
           linux-tools-common \
           linux-tools-generic \
           rpm \
           musl-tools \
   ``` 
3. Install 'zip' package for build
   ```
   sudo apt install zip
   ```
4. Install dotnet package for build
   ```
   sudo snap install dotnet-sdk --classic
   sudo chown -R root:root /var/lib
   ```
## How to clone and build the project
This section outlines the steps to build, prepare and build this project.

### Cloning the project
1. Copy your ssh private & public key to the Linux VM
   ```
   scp -i "<path>\ssh.pem" "<path>\ssh.pem" <username>@<ip>:.ssh
   scp -i "<path>\ssh.pem" "<path>\ssh.pub" <username>@<ip>:.ssh
   ```
2. Rename the ssh files to id_rsa at Linux VM
   ```
   [ ~/.ssh ]$ mv ssh.pem id_rsa
   [ ~/.ssh ]$ mv ssh.pub id_rsa.pub
   ```
3. Add permissions to the ssh files
   ```
   [ ~/.ssh ]$ chmod 600 id_rsa
   [ ~/.ssh ]$ chmod 644 id_rsa.pub
   ```
4. [Add a SSH key to your GitHub account](https://docs.github.com/en/enterprise/2.15/user/articles/adding-a-new-ssh-key-to-your-github-account)

5. Clone the code
   ```
   git clone git@github.com:Azure/GuestProxyAgent.git
   ```
By default this will clone the project under the `GuestProxyAgent` directory.

### Build the project
Navigate to this repo root folder and run
   ```
   ./build-linux.sh
   ```

