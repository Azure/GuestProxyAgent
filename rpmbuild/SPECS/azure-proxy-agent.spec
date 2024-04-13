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

%prep
%setup -n %{name}_%{version}

%install
mkdir -p %{buildroot}/lib/systemd/system/
mkdir -p %{buildroot}/usr/lib/azure-proxy-agent/Package_%{version}/
cp -f ./package/GuestProxyAgent.service %{buildroot}/lib/systemd/system/
cp -f ./package/ProxyAgent/* %{buildroot}/usr/lib/azure-proxy-agent/Package_%{version}/

%post
ln -sf /usr/lib/azure-proxy-agent/Package_%{version} /usr/lib/azure-proxy-agent/package
ln -sf /usr/lib/azure-proxy-agent/package/GuestProxyAgent /usr/sbin/azure-proxy-agent
chcon -t bin_t /usr/lib/azure-proxy-agent/package/GuestProxyAgent
%systemd_post GuestProxyAgent.service
   systemctl daemon-reload
   systemctl start GuestProxyAgent.service
   systemctl enable GuestProxyAgent.service

%files
%defattr(-,root,root,-)
/lib/systemd/system/GuestProxyAgent.service
/usr/lib/azure-proxy-agent/Package_%{version}/GuestProxyAgent
/usr/lib/azure-proxy-agent/Package_%{version}/GuestProxyAgent.json
/usr/lib/azure-proxy-agent/Package_%{version}/ebpf_cgroup.o

%changelog
* Initial release 