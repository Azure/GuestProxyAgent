// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define AF_INET 2
#define AF_INET6 0x17

typedef struct _ip_address
{
    union
    {
        uint32_t ipv4;
        uint32_t ipv6[4];
    };
} ip_address_t;

typedef struct _destination_entry
{
    ip_address_t destination_ip;
    uint16_t destination_port;
    uint32_t protocol;
} destination_entry_t;

typedef struct _sock_addr_aduit_key{
    uint32_t protocol;
    uint16_t source_port;
}sock_addr_aduit_key_t;

typedef struct _sock_addr_audit_entry{
    uint64_t logon_id;
    uint32_t process_id;
    int32_t is_admin;
    uint32_t destination_ipv4;
    uint16_t destination_port;
}sock_addr_audit_entry_t;

typedef struct _sock_addr_skip_process_entry{
    uint32_t pid;
}sock_addr_skip_process_entry;