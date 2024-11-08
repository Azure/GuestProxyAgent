%global __os_install_post %{nil}

Name:           azure-proxy-agent
Version:        %{pkgversion}
Release:        0
Summary:        Azure Proxy Agent

License:        MIT
URL:            https://github.com/Azure/GuestProxyAgent
Source0:        %{name}_%{version}.tar.gz

%description
Microsoft Azure Guest Proxy Agent.

%define _buildshell /bin/bash

%prep
%setup -n %{name}_%{version}

%install
mkdir -p %{buildroot}/usr/sbin/
mkdir -p %{buildroot}/etc/azure/
mkdir -p %{buildroot}/usr/lib/systemd/system/
mkdir -p %{buildroot}/usr/lib/azure-proxy-agent/
cp -f ./package/ProxyAgent/proxy-agent.json %{buildroot}/etc/azure/
cp -f ./package/azure-proxy-agent.service %{buildroot}/usr/lib/systemd/system/
cp -f ./package/ProxyAgent/ebpf_cgroup.o %{buildroot}/usr/lib/azure-proxy-agent/
cp -f ./package/ProxyAgent/azure-proxy-agent %{buildroot}/usr/sbin/

%post
%systemd_post azure-proxy-agent.service
   systemctl unmask azure-proxy-agent.service
   systemctl daemon-reload
   systemctl start azure-proxy-agent.service
   systemctl enable azure-proxy-agent.service

%files
%defattr(-,root,root,-)
/usr/lib/systemd/system/azure-proxy-agent.service
/usr/sbin/azure-proxy-agent
/etc/azure/proxy-agent.json
/usr/lib/azure-proxy-agent/ebpf_cgroup.o

%changelog
* Fri Sep 13 23:43:30 UTC 2024 - ARTProxyAgentVTeam@microsoft.com

- Initial release
