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
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using symbolresolver;

namespace UnitTests
{
    [TestClass]
    public class UserModeSymbol
    {
        // Integration tests — they touch the real dbghelp DLL, spawn symbol
        // lookups, and hit msdl.microsoft.com. Serialize them because dbghelp
        // uses per-process global state for the sym handle and concurrent
        // resolvers stomp on each other.
        [TestMethod]
        public async Task Initialize_Succeeds()
        {
            using var resolver = new SymbolResolver(SharedFixtures.SymbolPath, SharedFixtures.DbgHelpDirectory);
            Assert.IsTrue(await resolver.Initialize(),
                "SymbolResolver.Initialize() returned false for the current user.");
        }

        [TestMethod]
        public async Task Dispose_IsSafeWithoutInitialize()
        {
            // Regression: disposing before Initialize should not throw —
            // SymCleanup is only called when m_SymHandle is non-zero.
            var resolver = new SymbolResolver(SharedFixtures.SymbolPath, SharedFixtures.DbgHelpDirectory);
            await Task.Yield();
            resolver.Dispose();
        }

        [TestMethod]
        public async Task ResolveUserAddress_ResolvesAddressInsideOwnProcess()
        {
            using var resolver = new SymbolResolver(SharedFixtures.SymbolPath, SharedFixtures.DbgHelpDirectory);
            Assert.IsTrue(await resolver.Initialize());

            var (pid, address) = PickOwnProcessAddress();

            var resolved = await resolver.ResolveUserAddress(
                pid, address, SymbolFormattingOption.SymbolAndModule);

            Assert.IsNotNull(resolved);
            Assert.IsFalse(string.IsNullOrWhiteSpace(resolved),
                "Expected a non-empty resolved string for an address inside the test process.");
        }

        [TestMethod]
        public async Task ResolveUserAddress_ReturnsUnknownForInvalidAddress()
        {
            using var resolver = new SymbolResolver(SharedFixtures.SymbolPath, SharedFixtures.DbgHelpDirectory);
            Assert.IsTrue(await resolver.Initialize());

            var currentPid = Process.GetCurrentProcess().Id;
            // Kernel-space address — from a user-mode process this will never resolve.
            var resolved = await resolver.ResolveUserAddress(
                currentPid, 0xFFFFFFFF_DEADBEEFUL, SymbolFormattingOption.SymbolAndModule);

            // The resolver returns an "<unknown_0x...>" string rather than
            // throwing; make sure that contract still holds so consumers can
            // safely include the result in log messages.
            Assert.IsNotNull(resolved);
            StringAssert.Contains(resolved, "unknown");
        }

        [TestMethod]
        public async Task ResolveUserAddress_HandlesExitedProcess()
        {
            using var resolver = new SymbolResolver(SharedFixtures.SymbolPath, SharedFixtures.DbgHelpDirectory);
            Assert.IsTrue(await resolver.Initialize());

            // Spawn-and-exit a short-lived process so we have a pid that was
            // once real but no longer is. PID recycling on Windows is rare
            // within a second, so this is safe for a single synchronous test.
            var psi = new ProcessStartInfo("cmd.exe", "/c exit 0")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
            };
            using var proc = Process.Start(psi)!;
            proc.WaitForExit(5000);
            var deadPid = proc.Id;

            // The contract for an exited process is "don't crash" — the
            // resolver may return null (OpenProcess failed) or a fallback
            // string. Either is acceptable; the test just guards against
            // an unhandled exception bubbling out of the library.
            var resolved = await resolver.ResolveUserAddress(
                deadPid, 0x12345678UL, SymbolFormattingOption.SymbolAndModule);

            // Reaching this line is the assertion.
            _ = resolved;
        }

        private static (int Pid, ulong Address) PickOwnProcessAddress()
        {
            // Resolving against the test process itself gives a stable,
            // CI-portable target — no dependency on a specific running
            // system process.
            var self = Process.GetCurrentProcess();
            var module = self.Modules
                .Cast<ProcessModule>()
                .FirstOrDefault(m => m.ModuleName?.ToLowerInvariant() == "kernel32.dll")
                ?? self.MainModule;

            Assert.IsNotNull(module, "Test host has no modules — cannot pick an address to resolve.");

            // Offset a few hundred bytes into the module so we're past the
            // DOS header and inside real code.
            return (self.Id, (ulong)module!.BaseAddress.ToInt64() + 0x400);
        }
    }
}
