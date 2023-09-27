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
using symbolresolver;

namespace UnitTests
{
    [TestClass]
    public class KernelModeSymbol
    {
        private readonly string s_DbgHelpLocation = @"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll";
        private readonly string s_SymbolPath = @"srv*c:\symbols*https://msdl.microsoft.com/download/symbols";

        [TestMethod]
        public void Basic()
        {
            SymbolResolver resolver = null;
            ulong address = 0;
            try
            {
                resolver = new SymbolResolver(s_SymbolPath, s_DbgHelpLocation);
                resolver.Initialize();
                var drivers = resolver.GetLoadedKernelDrivers();
                Assert.IsNotNull(drivers);
                Assert.IsTrue(drivers.Count > 0);
                var kernel = drivers.FirstOrDefault(d => d.ImagePath.ToLower().Contains("ntos"));
                if (kernel == null)
                {
                    kernel = drivers.FirstOrDefault(d => d.ImagePath.ToLower().Contains("ntkr"));
                }
                Assert.IsNotNull(kernel);
                address = kernel.BaseAddress + 100;
            }
            catch (InvalidOperationException ex)
            {
                Assert.Fail($"Unable to init SymbolResolver: {ex.Message}");
            }

            Assert.AreNotEqual(0UL, address);
            var result = resolver.GetFormattedSymbol(address);
            Assert.IsTrue(!string.IsNullOrEmpty(result));
        }
    }
}