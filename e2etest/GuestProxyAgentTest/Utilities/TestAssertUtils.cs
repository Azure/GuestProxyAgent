// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GuestProxyAgentTest.Utilities
{
    public static class TestAssertUtils
    {
        public static void AssertIsTrue(Func<bool> func, string message)
        {
            if (!func())
            {
                throw new Exception("Test Assert failed: " + message);
            }
        }
    }
}
