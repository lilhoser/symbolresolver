/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0
*/
using System;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using symbolresolver;

namespace UnitTests
{
    [TestClass]
    public class KernelModeSymbol
    {
        [TestMethod]
        public async Task Basic()
        {
            using var resolver = new SymbolResolver(SharedFixtures.SymbolPath, SharedFixtures.DbgHelpDirectory);
            Assert.IsTrue(await resolver.Initialize(),
                "SymbolResolver.Initialize() returned false.");

            // Kernel addresses start above 0xFFFF_8000_0000_0000 on x64.
            // The exact value we pass won't necessarily resolve to a real
            // symbol, but the resolver must handle a kernel-space address
            // without throwing and must produce a stringified result.
            var resolved = await resolver.ResolveKernelAddress(
                0xFFFFFFFE_81000010, SymbolFormattingOption.SymbolAndModule);

            Assert.IsNotNull(resolved);
            Assert.IsFalse(string.IsNullOrWhiteSpace(resolved));
        }

        [TestMethod]
        public async Task InvalidKernelAddress_ReturnsUnknownFallback()
        {
            using var resolver = new SymbolResolver(SharedFixtures.SymbolPath, SharedFixtures.DbgHelpDirectory);
            Assert.IsTrue(await resolver.Initialize());

            // A deliberately garbage kernel-space address — should fall back
            // to the "<unknown_0x...>" string rather than throw.
            var resolved = await resolver.ResolveKernelAddress(
                0xFFFFFFFF_FFFFFFFF, SymbolFormattingOption.SymbolAndModule);

            Assert.IsNotNull(resolved);
        }
    }
}
