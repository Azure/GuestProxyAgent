#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT


echo ======= Get the directory of the script
root_path="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
out_path=$root_path"/out"
echo "Set out_path to: $out_path"
build_target="x86_64-unknown-linux-musl"

echo ======= Set Build Configuration
Configuration=$1
if [ "$Configuration" != "release" ] 
then 
    Configuration="debug"
fi
out_dir=$out_path/$build_target/$Configuration
echo "The out_dir is: $out_dir"

release_flag=""
if [ "$Configuration" = "release" ]
then 
    release_flag="--release"
fi

CleanBuild=$2
if [ "$CleanBuild" = "clean" ] 
then 
    echo ======= delete old files
    echo rm -rf $out_dir
    rm -rf $out_dir
fi

echo ======= rustup component add rust-std-x86_64-unknown-linux-musl
rustup component add rust-std-x86_64-unknown-linux-musl
rustup update stable
cargo install cargo-deb

echo ======= build proxy_agent_shared
cargo_toml=$root_path/proxy_agent_shared/Cargo.toml
echo cargo_toml=$cargo_toml
echo invoking cargo build $release_flag --manifest-path $cargo_toml --target-dir $out_path --target $build_target
cargo build $release_flag --manifest-path $cargo_toml --target-dir $out_path --target $build_target
error_code=$?
if [ $error_code -ne 0 ]
then 
    echo "cargo build proxy_agent_shared failed with exit-code: $error_code"
    exit $error_code
fi

echo ======= run rust proxy_agent_shared tests
echo invoking cargo test $release_flag --target $build_target --manifest-path $cargo_toml --target-dir $out_path -- --test-threads=1
cargo test $release_flag --target $build_target --manifest-path $cargo_toml --target-dir $out_path -- --test-threads=1
error_code=$?
if [ $error_code -ne 0 ]
then 
    echo "cargo test proxy_agent_shared with exit-code: $error_code"
    exit $error_code
fi

echo ======= build ebpf program after the proxy_agent_shared is built to let $out_dir created. 
echo ======= build ebpf program for x64_x86 platform
ebpf_path=$root_path/linux-ebpf
echo invoking clang -g -target bpf -Werror -O2 -D__TARGET_ARCH_x86 -c $ebpf_path/ebpf_cgroup.c -o $out_dir/ebpf_cgroup.o
clang -g -target bpf -Werror -O2 -D__TARGET_ARCH_x86 -c $ebpf_path/ebpf_cgroup.c -o $out_dir/ebpf_cgroup.o
error_code=$?
if [ $error_code -ne 0 ]
then 
    echo "call clang failed with exit-code: $error_code"
    exit $error_code
fi
llvm-objdump -h $out_dir/ebpf_cgroup.o
ls -l $out_dir/ebpf_cgroup.o

echo ======= build proxy_agent
cargo_toml=$root_path/proxy_agent/Cargo.toml
echo cargo_toml=$cargo_toml
echo invoking cargo build $release_flag --manifest-path $cargo_toml --target-dir $out_path --target $build_target
cargo build $release_flag --manifest-path $cargo_toml --target-dir $out_path --target $build_target
error_code=$?
if [ $error_code -ne 0 ]
then 
    echo "cargo build proxy_agent failed with exit-code: $error_code"
    exit $error_code
fi

echo ======= copy config file for Linux platform
cp -f -T $root_path/proxy_agent/config/GuestProxyAgent.linux.json $out_dir/GuestProxyAgent.json

echo ======= copy files for run/debug proxy_agent Unit test
echo cp -f $out_dir/* $out_dir/deps/
cp -f $out_dir/* $out_dir/deps/
echo cp -f -r $out_dir/* $root_path/proxy_agent/target/$Configuration/
cp -f -r $out_dir/* $root_path/proxy_agent/target/$Configuration/

echo ======= run rust proxy_agent tests
echo invoking cargo test $release_flag --target $build_target --manifest-path $cargo_toml --target-dir $out_path -- --test-threads=1
cargo test $release_flag --target $build_target --manifest-path $cargo_toml --target-dir $out_path -- --test-threads=1
error_code=$?
if [ $error_code -ne 0 ]
then 
    echo "cargo test proxy_agent with exit-code: $error_code"
    exit $error_code
fi

echo ======= build proxy_agent_extension
cargo_toml=$root_path/proxy_agent_extension/Cargo.toml
extension_src_path=$root_path/proxy_agent_extension/src/linux
echo cargo_toml=$cargo_toml
echo invoking cargo build $release_flag --manifest-path $cargo_toml --target-dir $out_path --target $build_target
cargo build $release_flag --manifest-path $cargo_toml --target-dir $out_path --target $build_target
error_code=$?
if [ $error_code -ne 0 ]
then 
    echo "cargo build proxy_agent_extension failed with exit-code: $error_code"
    exit $error_code
fi

echo ======= copy files for run/debug proxy_agent_extension Unit test
echo cp -f $out_dir/* $out_dir/deps/
cp -f $out_dir/* $out_dir/deps/
echo cp -f -r $out_dir/* $root_path/proxy_agent_extension/target/$Configuration/
cp -f -r $out_dir/* $root_path/proxy_agent_extension/target/$Configuration/

echo ======= run rust proxy_agent_extension tests
echo invoking cargo test $release_flag --target $build_target --manifest-path $cargo_toml --target-dir $out_path -- --test-threads=1
cargo test $release_flag --target $build_target --manifest-path $cargo_toml --target-dir $out_path -- --test-threads=1
error_code=$?
if [ $error_code -ne 0 ]
then 
    echo "cargo test proxy_agent_extension with exit-code: $error_code"
    exit $error_code
fi

echo ======= copy config file for Linux platform
cp -f -r $root_path/proxy_agent_setup/src/linux/* $out_dir/
echo ======= build proxy_agent_setup
cargo_toml=$root_path/proxy_agent_setup/Cargo.toml
echo cargo_toml=$cargo_toml
echo invoking cargo build $release_flag --manifest-path $cargo_toml --target-dir $out_path --target $build_target
cargo build $release_flag --manifest-path $cargo_toml --target-dir $out_path --target $build_target
error_code=$?
if [ $error_code -ne 0 ]
then 
    echo "cargo build proxy_agent_setup failed with exit-code: $error_code"
    exit $error_code
fi
echo ======= copy files for run/debug proxy_agent_setup Unit test
echo cp -f $out_dir/* $out_dir/deps/
cp -f $out_dir/* $out_dir/deps/
echo cp -f -r $out_dir/* $root_path/proxy_agent_setup/target/$Configuration/
cp -f -r $out_dir/* $root_path/proxy_agent_setup/target/$Configuration/

echo ======= build e2e test solution
echo dotnet build $root_path/e2etest/GuestProxyAgentTest.sln --configuration $Configuration -o $out_dir/e2etest
dotnet build $root_path/e2etest/GuestProxyAgentTest.sln --configuration $Configuration -o $out_dir/e2etest
error_code=$?
if [ $error_code -ne 0 ]
then 
    echo "dotnet build failed with exit-code: $error_code"
    exit $error_code
fi

echo ======= prepare out-package folder structure
out_package_dir=$out_dir/package
if [ ! -d $out_package_dir ]; then
  mkdir $out_package_dir
fi
echo ======= copy to package folder
cp -f $out_dir/proxy_agent_setup $out_package_dir/
cp -f $out_dir/GuestProxyAgent.service $out_package_dir/

out_package_proxyagent_dir=$out_package_dir/ProxyAgent
if [ ! -d $out_package_proxyagent_dir ]; then
  mkdir $out_package_proxyagent_dir
fi

echo ======= copy to proxyagent folder
cp -f $out_dir/GuestProxyAgent $out_package_proxyagent_dir/
cp -f $out_dir/GuestProxyAgent.json $out_package_proxyagent_dir/
cp -f $out_dir/ebpf_cgroup.o $out_package_proxyagent_dir/

echo ======= generate rpm package
echo "Generating rpm package -------------- "
pkgversion=$($out_dir/GuestProxyAgent --version)
echo "Package version: '$pkgversion'"
rootdir=$(pwd)
rm -rf build
mkdir build
pushd build
    mkdir GuestProxyAgent
    pushd GuestProxyAgent
        cp -rf $out_package_dir/ ./
    popd
    mv GuestProxyAgent azure-proxy-agent_${pkgversion}
    tar -czf azure-proxy-agent_${pkgversion}.tar.gz azure-proxy-agent_${pkgversion}
popd
pushd rpmbuild
    mkdir SOURCES BUILD RPMS SRPMS
    cp ../build/azure-proxy-agent_${pkgversion}.tar.gz SOURCES/
    rpmbuild --define "_topdir ${rootdir}/rpmbuild" --define "pkgversion ${pkgversion}" -ba SPECS/azure-proxy-agent.spec
    error_code=$?
    if [ $error_code -ne 0 ]
    then 
        echo "rpmbuild failed with exit-code: $error_code"
        exit $error_code
    fi
popd
rm -rf build 
echo ======= copy rpm package file to Package folder
cp -f $rootdir/rpmbuild/RPMS/x86_64/azure-proxy-agent-${pkgversion}-0.x86_64.rpm $out_package_dir/

echo ======= generate deb package
echo "Generating deb package -------------- "
rm -rf debbuild
mkdir debbuild
pushd debbuild
    mkdir -p DEBIAN src
    cp -rf $rootdir/debian/* ./DEBIAN/
    cp -rf $rootdir/proxy_agent/Cargo.toml ./Cargo.toml
    cp -rf $rootdir/proxy_agent/src/* ./src/    # cargo deb --no-build command still requires ./src/main.rs
    cp -f $out_package_proxyagent_dir/GuestProxyAgent ./
    cp -f $out_package_proxyagent_dir/GuestProxyAgent.json ./
    cp -f $out_package_proxyagent_dir/ebpf_cgroup.o ./
    cp -f $out_package_dir/GuestProxyAgent.service ./DEBIAN/
    sed -i "s/pkgversion/${pkgversion}/g" DEBIAN/control  # replace pkgversion with actual version
    sed -i "s/pkgversion/${pkgversion}/g" DEBIAN/postinst  # replace pkgversion with actual version
    sed -i "s/pkgversion/${pkgversion}/g" Cargo.toml  # replace pkgversion with actual version
    echo cargo deb -v --manifest-path $rootdir/debbuild/Cargo.toml --no-build -o $out_package_dir --target $build_target
    cargo deb -v --manifest-path $rootdir/debbuild/Cargo.toml --no-build -o $out_package_dir --target $build_target
    error_code=$?
    if [ $error_code -ne 0 ]
    then 
        echo "cargo deb: failed with exit-code: $error_code"
        exit $error_code
    fi
popd
rm -rf debbuild

echo ======= copy to proxyagent extension folder 
out_package_proxyagent_extension_dir=$out_package_dir/ProxyAgent_Extension
if [ ! -d $out_package_proxyagent_extension_dir ]; then
  mkdir $out_package_proxyagent_extension_dir
fi
cp -f $extension_src_path/HandlerManifest.json $out_package_proxyagent_extension_dir/
for f in $extension_src_path/*.sh; do
    cp -f $f $out_package_proxyagent_extension_dir/
done
cp -f $out_dir/ProxyAgentExt $out_package_proxyagent_extension_dir/

echo ======= copy e2e test project to Package folder
cp -rf $out_dir/e2etest/ $out_package_dir/e2etest/

echo ======= Generate build-configuration-linux-amd64.zip file with relative path within the zip file
cd $out_package_dir
zip -r $out_dir/build-$Configuration-linux-amd64.zip .
