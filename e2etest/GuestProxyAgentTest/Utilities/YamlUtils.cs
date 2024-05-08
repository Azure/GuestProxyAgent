// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using YamlDotNet.Serialization.NamingConventions;
using YamlDotNet.Serialization;

namespace GuestProxyAgentTest.Utilities
{
    public static class YamlUtils
    {
        public static T DeserializeYaml<T>(string filePath)
        {
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .Build();
            using (var reader = new StreamReader(filePath))
            {
                return deserializer.Deserialize<T>(reader.ReadToEnd());
            }
        }
    }
}
