// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#define BPF_SOCK_ADDR_VERDICT_PROCEED 1
#define IPPROTO_TCP 6
#define AF_INET 2 

typedef struct _sock_addr_skip_process_entry
{
    __u32 pid;
} sock_addr_skip_process_entry;

typedef struct _ip_address
{
    union
    {
        __u32 ipv4;
        __u32 ipv6[4];
    };
} ip_address;

typedef struct _destination_entry
{
    ip_address destination_ip;
    __u32 destination_port;
    __u32 protocol;
} destination_entry;

typedef struct _sock_addr_aduit_key
{
    __u32 protocol;
    __u32 source_port;
} sock_addr_aduit_key;

typedef struct _sock_addr_audit_entry
{
    __u32 logon_id;
    __u32 process_id;
    __u32 is_root;
    __u32 destination_ipv4;
    __u32 destination_port;
} sock_addr_audit_entry;

typedef struct _bpf_sock_tuple_ipv4
{
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
} bpf_sock_tuple_ipv4;

typedef struct _sock_addr_local_entry
{
    __u32 logon_id;
    __u32 process_id;
    __u32 is_root;
    __u32 destination_ipv4;
    __u32 destination_port;
    __u32 protocol;
} sock_addr_local_entry;

typedef __u32 __bitwise __portpair;
typedef __u64 __bitwise __addrpair;

struct hlist_node
{
    struct hlist_node *next, **pprev;
};

struct sock_common
{
    union
    {
        __addrpair skc_addrpair;
        struct
        {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union
    {
        unsigned int skc_hash;
        __u16 skc_u16hashes[2];
    };
    /* skc_dport && skc_num must be grouped as well */
    union
    {
        __portpair skc_portpair;
        struct
        {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };

    unsigned short skc_family;
    volatile unsigned char skc_state;
    unsigned char skc_reuse : 4;
    unsigned char skc_reuseport : 1;
    unsigned char skc_ipv6only : 1;
    unsigned char skc_net_refcnt : 1;
    int skc_bound_dev_if;
    union
    {
        struct hlist_node skc_bind_node;
        struct hlist_node skc_portaddr_node;
    };
};

struct probe_sock
{
    struct sock_common __sk_common;
};