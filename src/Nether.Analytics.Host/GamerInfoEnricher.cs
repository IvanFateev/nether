﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Nether.Analytics.Parsers;
using System;
using System.Threading.Tasks;

namespace Nether.Analytics.Host
{
    public class GamerInfoEnricher : IMessageHandler
    {
        public Task<MessageHandlerResults> ProcessMessageAsync(Message msg, string pipelineName, int index)
        {
            msg.Properties.Add("Greeting", $"Event was enriched in pipeline {pipelineName}");

            return Task.FromResult(MessageHandlerResults.Success);
        }
    }
}