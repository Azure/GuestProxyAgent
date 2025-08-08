// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
namespace GuestProxyAgentTest.Utilities
{
    public class ResourceNamer
    {
        private readonly string randName;

        private static string[] formats = new string[1] { "M/d/yyyy h:mm:ss tt" };

        private static Random random = new Random();

        public ResourceNamer(string name)
        {
            lock (random)
            {
                randName = name.ToLower() + Guid.NewGuid().ToString("N").Substring(0, 3)
                    .ToLower();
            }
        }

        public virtual string RandomName(string prefix, int maxLen)
        {
            lock (random)
            {
                prefix = prefix.ToLower();
                int num = 5;
                string text = random.Next(0, 100000).ToString("D5");
                if (maxLen < prefix.Length + randName.Length + num)
                {
                    string text2 = prefix + text;
                    return text2 + RandomString((maxLen - text2.Length) / 2);
                }

                string text3 = prefix + randName + text;
                return text3 + RandomString((maxLen - text3.Length) / 2);
            }
        }

        private string RandomString(int length)
        {
            string text = "";
            while (text.Length < length)
            {
                text += Guid.NewGuid().ToString("N").Substring(0, Math.Min(32, length))
                    .ToLower();
            }

            return text;
        }

        public string RandomGuid()
        {
            return Guid.NewGuid().ToString();
        }
    }
}
