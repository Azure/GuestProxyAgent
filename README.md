# Microsoft Azure Guest Proxy Agent

## Introduction
This project introduces new features to better secure HTTP calls to a couple of network endpoints (WireServer IP Endpoint [168.63.129.16] and Instance Metadata Service IP Endpoint [169.254.169.254]) [Advanced authorization feature still under design] accessible from within Azure VMs. It introduces a new component (GuestProxyAgent) which leverages [eBPF](https://ebpf.io/what-is-ebpf/) to intercept the http query, and control the access at two levels:
 - Default admin/root only authorization for the (WireServer) endpoints: 168.63.129.16. Instead of using firewall rules for the admin/root process authorization check, we will be using the GuestProxyAgent. 
 - Advanced authorization where only approved communication is allowed via the GuestProxyAgent. Authorization is configurable though a policy that generates an allowed list, by user id, process name etc. [Feature still under design]  

eBPF is well-known technology for providing programmability and agility, especially for extending an OS kernel. It is used to extend the capabilities of the kernel safely and efficiently without requiring changes to kernel source code or loading kernel modules. This project depends on [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows) for Windows VMs; it requires kernel version 5.15+ for Linux VMs which has our required eBPF features.

This project supports Azure VMs on Windows 10 or later, and on Windows Server 2019 or later, Ubuntu20 or later, Redhat 9 or later, flatcar, Rocky-Linux9, Suse 15 SP4 or later. To build this project on Windows see [Getting Started Guide - Windows](doc/GettingStarted.md), To build this project on Linux, see [Getting Started Guide - Ubuntu 22](doc/GettingStarted-Linux.md).

## Architectural Overview
The following diagram shows the basic architecture of this project and related components:

![Architectural Overview](doc/GuestProxyAgent.png)

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Telemetry

Its goal is to quickly and automatically send diagnostics telemetry events from a VM, so they can be used for offline analysis. The collected events are Azure GuestProxyAgent logs, Engineering teams and support professionals can then use those telemetry entries to investigate issues.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
