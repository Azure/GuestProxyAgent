// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GuestProxyAgentTest.Models
{
    public class TestConfig
    {
        public string TenantId { get; set; } = null!;
        public string AppClientId { get; set; } = null!;
        public string CertThumbprint { get; set; } = null!;
        public string CertNameInKV { get; set; } = "GuestProxyAgentE2ETestCert";
        public string SubscriptionId { get; set; } = null!;
        public string Location { get; set; } = null!;
        public string VmSize { get; set; } = null!;
        public string SharedStorageAccountUrl { get; set; } = null!;
    }
}
