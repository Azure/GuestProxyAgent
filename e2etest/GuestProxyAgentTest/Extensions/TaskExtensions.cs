// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

namespace GuestProxyAgentTest.Extensions
{
    public static class TaskExtensions
    {
        public static async Task TimeoutAfter(this Task task, int timeoutMilliSeconds, CancellationTokenSource cancellationTokenSource = null!)
        {
            if (task == await Task.WhenAny(task, Task.Delay(timeoutMilliSeconds)))
            {
                await task;
            }
            else
            {
                if (cancellationTokenSource != null)
                {
                    // Cancel the task
                    cancellationTokenSource.Cancel();
                }
                throw new TimeoutException("task time out.");
            }
        }
    }
}
