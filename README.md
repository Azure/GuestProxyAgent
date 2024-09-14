# Microsoft Azure Guest Proxy Agent

## Introduction

This project a new component, the Guest Proxy Agent (GPA) to enhance the security of the Azure Instance Metadata Service
and Azure Wireserver endpoints (available in Azure IaaS VMs at `169.254.169.254` and `168.63.129.16` respectively).

These endpoints provide metadata and credential bootstrapping for VMs, and an analogous offering exists from the majority
of cloud providers. As a result they are frequently targeted by threat actors. Common vectors include SSRF, confused
deputies, and sandbox escapes (particularly with nested and hosted-on-behalf-of workloads).

While numerous defense in depth strategies exist, even when applied these services continue to provide secrets over an
unauthenticated HTTP API which carries inherent risk. This project closes many of the most common vulnerabilities by
introducing true Authentication (AuthN) and Authorization (AuthZ) concepts to cloud metadata services.

With metadata services, the trust boundary is the VM itself. Any software within the guest is authorized to request
secrets from IMDS. VM owners are responsible for carefully sandboxing any software they run inside the VM, and ensuring
that external actors can't exfiltrate data. This is achievable, but in practice the complexity of the problem leads to
mistakes which can lead to exploits.

## Implementation

The GPA hardens against these type of attacks by:

- Limiting metadata access to a subset of the VM (applying the principle of least privileged access)
- Switching from a "default-open" to "default-closed" model. For instance, with nested virtualization a misconfigured L2
  VM that has access to the L1 VM's vNIC can communicate with a metadata service as the L1. With the GPA, a misconfigured
  L2 would no longer be able to gain access, as it would be unable to authenticate with the service.

At provisioning time the metadata service establishes as trusted delegate within the guest (the GPA).
A long-lived secret established to authenticate with the trusted delegate, and all requests to the metadata service must
be endorsed by the delegate (using an HMAC). This establishes a point-to-point trust relationship with strong AuthN.

The GPA leverages [eBPF](https://ebpf.io/what-is-ebpf/) to intercept HTTP requests to the metadata services. eBPF
enables the GPA to authoritatively verify the identity of the in guest software that made the request without introducing
an additional kernel module. Using this information, it compares the identity of the client against an allow list defined
as a part of the VM model and endorses requests that are authorized by transparently adding a signature header.

- By default, the existing authorization levels are enforced: IMDS is open to all users and Wireserver is root / admin only.
  - Today this restriction is accomplished with firewall rules in the guest, a default-open mechanism. The AuthN mechanism
    enabled here is far more resilient.
- Advanced AuthZ configuration to authorize specific in-guest processes and users to access only specific endpoints is
  supported by defining a custom allow list with RBAC semantics.

## Compatibility

eBPF is available in Linux kernels 5.15+ and on Windows VMs with [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows).

This project supports Azure VMs running:
 
- Windows 10 or later
- Windows Server 2019 or later
- Ubuntu20+
- Redhat 9+
- Flatcar
- Rocky-Linux9+
- SUSE 15 SP4+

## Architectural Overview

The following diagram shows the basic architecture of this project and related components:

![Architectural Overview](doc/GuestProxyAgent.png)

## Development

### Prerequisites

Ensure you have `docker-compose` installed and can download ~3-10GB on first run. The repo provides a build image for
Linux and one for Windows. The container pre-configures all dependencies for you, so compiling outside them is not
recommended. Clone the repo locally, then launch the container. Your local repo will be mounted automatically.

### Developing for Linux Targets

We use Ubuntu as the base image. The same dockerfile is likely to work on other distros with minimal tweaking, but only
the provided configuration is validated.

```shell
docker-compose -f docker-compose-linux.yml run --build -it dev
```

Within the attached container, the full build, all tests, and all packaging can be run with:

```shell
chmod +x ./build-linux.sh
./build-linux.sh
```

> If you are on Windows using WSL2 to host your container. The linux headers package isn't available under WSL2, so the
> generic package will be used instead. If you're still having issues building, or generic doesn't work with a different
> base image, you can disable the WSL2 backend in Docker Destkop's settings (note this will come with a performance
> penalty).

### Developing for Windows Targets

```shell
docker-compose -f docker-compose-windows.yml run --build -it dev
```

Within the attached container, the full build, all tests, and all packaging can be run with:

```shell
./build.cmd
```

> In certain Windows environments (e.g. using VM as the docker host) you may notice inordinately slow downloads during
> the docker image build. If you are in one of these edge cases, consider disabling RCS which [can potentially help](https://github.com/microsoft/Windows-Containers/issues/145):
> `powershell "Get-NetAdapterRSC | Disable-NetAdapterRSC"`

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

Its goal is to quickly and automatically send diagnostics telemetry events from a VM, so they can be used for offline
analysis. The collected events are Azure GuestProxyAgent logs, Engineering teams and support professionals can then use
those telemetry entries to investigate issues.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft
sponsorship. Any use of third-party trademarks or logos are subject to those third-party's policies.
