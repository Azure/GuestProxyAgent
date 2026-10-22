# Important

The drive 'redirect.bpf.sys' must be signed manually currently, so if we have to make any code changes within this folder, we need manual sign the 'redirect.bpf.sys' from the build output folder.

## Get the new 'redirect.bpf.sys'

1. To get the release version of new redirect.bpf.sys from your local dev box, run ```build release clean```. 
2. copy the './out/release/redirect.bpf.sys' to sign it manually.

## Manual Sign the new 'redirect.bpf.sys'

<< To be defined later >>

## Connection-bound audit correlation

The Windows and Linux audit maps use `(protocol, source port, source address
family, source IP address)` keys, with 16 bytes reserved for the address.
IPv4 uses the first address word and zeros the remaining words; IPv4-mapped
IPv6 peers normalize to the same IPv4 key. Native IPv6 uses all four words
and a distinct family. Both
lookup and removal require the complete key, so a direct connection from
another local address cannot read or consume a redirected caller's identity.
Missing entries follow the existing unauthenticated-connection rejection path
(HTTP 421).

Linux captures the selected source address at `tcp_connect`, after automatic
source selection. Windows uses socket-bound redirect context when either the
source port or source address is not yet selected, including wildcard binds.

Deploy the updated agent and eBPF program together (and sign the Windows
driver as described above). The audit key ABI is now 28 bytes.
For compatibility with released Windows eBPF programs, the agent also supports
their original 8-byte `(protocol, source port)` keys for lookup and removal.
This legacy layout cannot distinguish same-port peers on different source
addresses and retains the cross-address identity-stealing vulnerability.
The source-bound mitigation requires deploying the updated eBPF program;
updating the agent alone does not fix connections correlated by legacy keys.
Unknown key sizes are also rejected.
Windows socket-bound redirect contexts remain supported.
The expanded source key does not enable native IPv6 destination redirection;
that still requires IPv6 policy and destination handling.
