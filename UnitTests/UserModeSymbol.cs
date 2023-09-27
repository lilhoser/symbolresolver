/* 
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;
using symbolresolver;

namespace UnitTests
{
    [TestClass]
    public class UserModeSymbol
    {
        private readonly string s_DbgHelpLocation = @"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll";
        private readonly string s_SymbolPath = @"srv*c:\symbols*https://msdl.microsoft.com/download/symbols";

        [TestMethod]
        public void Basic()
        {
            //
            // Pick a suitable user-mode process.
            //
            int pid = 0;
            ulong address = 0;

            foreach (var process in Process.GetProcesses())
            {
                if (process.Id == Process.GetCurrentProcess().Id)
                {
                    continue;
                }

                try
                {
                    if (process.Id == 0 || process.Id == 4 || process.Handle == nint.Zero)
                    {
                        continue;
                    }
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    continue; // probably access is denied
                }
                catch (InvalidOperationException)
                {
                    continue; // probably the process died
                }

                //
                // Pick a module
                //
                try
                {
                    var modules = process.Modules.Cast<ProcessModule>().ToList();
                    foreach (var module in modules)
                    {
                        address = (ulong)module.BaseAddress.ToInt64() + 100;
                        break;
                    }
                }catch(Exception){continue; }

                pid = process.Id;
                break;
            }

            Assert.AreNotEqual(0, pid);
            Assert.AreNotEqual(0UL, address);

            SymbolResolver resolver = null;
            try
            {
                resolver = new SymbolResolver(s_SymbolPath, s_DbgHelpLocation);
                resolver.Initialize();
                resolver.InitializeForProcess(pid);
            }
            catch (InvalidOperationException ex)
            {
                Assert.Fail($"Unable to init SymbolResolver: {ex.Message}");
            }

            var result = resolver.GetFormattedSymbol(address);
            Assert.IsTrue(!string.IsNullOrEmpty(result));
        }
    }
}