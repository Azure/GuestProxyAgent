// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

namespace GuestProxyAgentTest.Extensions
{
    public static class TaskExtensions
    {
        public static async Task TimeoutAfter(this Task task, int timeoutMilliSeconds)
        {
            if(task == await Task.WhenAny(task, Task.Delay(timeoutMilliSeconds)))
            {
                await task;
            }
            else
            {
                throw new TimeoutException("task time out.");
            }
        }
    }
}
