// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
namespace GuestProxyAgentTest.Models
{
    /// <summary>
    /// Test Result Details class
    /// </summary>
    public class TestCaseResultDetails
    {
        /// <summary>
        /// The std output, it would be a content string or a blob SAS url that contains the std output, indicated by <see cref="FromBlob"/> bool value
        /// </summary>
        public string StdOut { get; set; } = null!;
        /// <summary>
        /// The std error output, it would be a content string or a blob SAS url that contains the std error output, indicated by <see cref="FromBlob"/> bool value
        /// </summary>
        public string StdErr { get; set; } = null!;
        /// <summary>
        /// The customized output, it would be a content string or a blob SAS url that contains the customized output, indicated by <see cref="FromBlob"/> bool value
        /// </summary>
        public string CustomOut { get; set; } = null!;
        /// <summary>
        /// indicate the test result is success or failed.
        /// </summary>
        public bool Succeed { get; set; }
        /// <summary>
        /// The bool flag indicate the content of StdOut, StdErr and CustomOut should read from blob or directly
        /// </summary>
        public bool FromBlob { get; set; }

    }
}
