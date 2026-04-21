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
using System.IO;

namespace UnitTests
{
    /// <summary>
    /// Shared helpers for the integration tests. CI runners don't have the
    /// Windows SDK installed at the hardcoded path the old tests used, so the
    /// dbghelp location is discovered at runtime.
    /// </summary>
    internal static class SharedFixtures
    {
        /// <summary>
        /// Resolves a directory containing dbghelp.dll. Honours the
        /// SYMBOLRESOLVER_DBGHELP_DIR env var first so CI can pin a specific
        /// SDK install, then checks common SDK locations, and finally falls
        /// back to the system dbghelp (C:\Windows\System32) — the shipping
        /// copy works for symbol formatting even if it's older.
        /// </summary>
        public static string DbgHelpDirectory
        {
            get
            {
                var envOverride = Environment.GetEnvironmentVariable("SYMBOLRESOLVER_DBGHELP_DIR");
                if (!string.IsNullOrEmpty(envOverride) && File.Exists(Path.Combine(envOverride, "dbghelp.dll")))
                {
                    return envOverride;
                }

                foreach (var candidate in new[]
                {
                    @"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64",
                    @"C:\Program Files\Windows Kits\10\Debuggers\x64",
                    @"C:\Program Files (x86)\Windows Kits\11\Debuggers\x64",
                    @"C:\Program Files\Debugging Tools for Windows (x64)",
                    @"C:\Windows\System32",
                })
                {
                    if (File.Exists(Path.Combine(candidate, "dbghelp.dll")))
                    {
                        return candidate;
                    }
                }

                throw new FileNotFoundException(
                    "dbghelp.dll not found. Set SYMBOLRESOLVER_DBGHELP_DIR or install the Windows SDK Debugging Tools.");
            }
        }

        /// <summary>
        /// Per-run symbol cache directory. Isolated so parallel CI shards
        /// don't fight over a shared directory and slow agents don't hit
        /// download timeouts on later tests.
        /// </summary>
        public static string SymbolPath { get; } = BuildSymbolPath();

        private static string BuildSymbolPath()
        {
            var dir = Path.Combine(Path.GetTempPath(), "symbolresolver-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return $"srv*{dir}*https://msdl.microsoft.com/download/symbols";
        }

    }
}
