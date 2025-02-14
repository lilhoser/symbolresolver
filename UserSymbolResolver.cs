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

namespace symbolresolver
{
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using static NativeDefinitions;
    using static TraceLogger;

    internal class UserSymbolResolver : ModuleResolver,IDisposable
    {
        private Dictionary<int, List<ulong>> m_LoadedModules;
        private bool m_Disposed;

        public UserSymbolResolver()
        {
            m_LoadedModules = new Dictionary<int, List<ulong>>();
        }

        ~UserSymbolResolver()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (m_Disposed)
            {
                return;
            }

            m_Disposed = true;
            foreach (var kvp in m_LoadedModules)
            {
                var pid = kvp.Key;
                foreach (var module in kvp.Value)
                {
                    if (!SymUnloadModule64(m_SymHandle, module))
                    {
                        var code = Marshal.GetLastWin32Error();
                        var err = $"SymUnloadModule64 failed for PID {pid} / module 0x{module:X}: {code}";
                        Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                    }
                }
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public async Task<string?> Resolve(
            int ProcessId,
            ulong Address,
            SymbolFormattingOption Format,
            SymbolResolverFlags Flags
            )
        {
            //
            // Load the modules in this process space if not done already.
            //
            if (!await Load(ProcessId))
            {
                return null;
            }

            string? resolved;
            if (!base.Resolve(Address, out resolved, Format, Flags) ||
                string.IsNullOrEmpty(resolved))
            {
                return null;
            }
            return resolved;
        }

        private async Task<bool> Load(int ProcessId)
        {
            if (m_LoadedModules.ContainsKey(ProcessId))
            {
                if (m_LoadedModules[ProcessId].Count > 0)
                {
                    //
                    // This module was already loaded.
                    //
                    return true;
                }
                m_LoadedModules.Remove(ProcessId); // try again?
            }

            //
            // We have to open a handle to the process to get its loaded module list.
            // SymInitialize would also do the same thing with invasive mode.
            //
            nint handle;

            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"Opening target process {ProcessId}");

            try
            {
                handle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)ProcessId);
            }
            catch (Exception ex)
            {
                var err = $"Unable to open process ID {ProcessId}: {ex.Message}";
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                return false;
            }

            if (handle == nint.Zero)
            {
                var code = Marshal.GetLastWin32Error();
                if (code == 0x5)
                {
                    var err = $"Unable to open process ID {ProcessId}: access is denied";
                    Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                }
                else if (code == 0x57)
                {
                    //
                    // The process likely isn't running - this can happen if the source
                    // of our requestor is from an ETW containing a PID from a terminated
                    // process, as an example.
                    //
                    var err = $"Process {ProcessId} doesn't exist";
                    Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                }
                else
                {
                    var err = $"Unable to open process ID {ProcessId}:  0x{code:X}";
                    Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                }
                return false;
            }

            m_LoadedModules.Add(ProcessId, new List<ulong>());

            return await Task.Run(() =>
            {
                try
                {
                    //
                    // Enumerate all modules in this process
                    //
                    if (!IsWow64Process(handle, out bool isWow64))
                    {
                        var err = $"IsWow64Process failed:  " + $"0x{Marshal.GetLastWin32Error():X}";
                        Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                        return false;
                    }

                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Information,
                          $"Enumerating modules for process");

                    var modules = new nint[1024];
                    var size = modules.Length * nint.Size;
                    var modFilter = isWow64 ? EnumProcessModulesFilter.LIST_MODULES_32BIT :
                        EnumProcessModulesFilter.LIST_MODULES_64BIT;

                    if (!EnumProcessModulesEx(handle, modules, size, out int numModules, modFilter))
                    {
                        var err = $"EnumProcessModulesEx failed:  0x{Marshal.GetLastWin32Error():X}";
                        Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                        return false;
                    }

                    if (numModules == 0)
                    {
                        //
                        // Likely a frozen/suspended UWP process.
                        //
                        var err = $"Process {ProcessId} has no loaded modules";
                        Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                        return false;
                    }

                    //
                    // Module loading is best effort - if one fails, we continue.
                    //
                    foreach (var module in modules.Take(numModules / nint.Size))
                    {
                        var buffer = Marshal.AllocHGlobal(1024);
                        if (buffer == nint.Zero)
                        {
                            Trace(TraceLoggerType.Resolver, TraceEventType.Error, "Out of memory");
                            return false;
                        }

                        var fileNameSize = GetModuleFileNameEx(handle, module, buffer, 1024);
                        if (fileNameSize == 0)
                        {
                            Marshal.FreeHGlobal(buffer);
                            var err = $"GetModuleFileNameEx failed:  0x{Marshal.GetLastWin32Error():X}";
                            Trace(TraceLoggerType.Resolver, TraceEventType.Warning, err);
                            continue;
                        }

                        var fileName = Marshal.PtrToStringUni(buffer);
                        Marshal.FreeHGlobal(buffer);

                        //
                        // Get load address and size.
                        //
                        size = Marshal.SizeOf(typeof(MODULE_INFO));
                        buffer = Marshal.AllocHGlobal(size);
                        if (buffer == nint.Zero)
                        {
                            Trace(TraceLoggerType.Resolver, TraceEventType.Error, "Out of memory");
                            return false;
                        }

                        if (!GetModuleInformation(handle, module, buffer, (uint)size))
                        {
                            Marshal.FreeHGlobal(buffer);
                            var err = $"GetModuleInformation failed for {fileName}:  " +
                                $"0x{Marshal.GetLastWin32Error():X}";
                            Trace(TraceLoggerType.Resolver, TraceEventType.Warning, err);
                            continue;
                        }

                        var modInfo = (MODULE_INFO)Marshal.PtrToStructure(buffer, typeof(MODULE_INFO))!;
                        var baseAddress = modInfo.BaseOfDll;
                        var imageSize = modInfo.SizeOfImage;
                        Marshal.FreeHGlobal(buffer);

                        if (baseAddress == 0 || imageSize == 0)
                        {
                            //
                            // This happens with modules loaded as data/image files.
                            //
                            var err = $"The module {fileName} in the process has invalid " +
                                $"base address ({baseAddress} or size ({imageSize})";
                            Trace(TraceLoggerType.Resolver, TraceEventType.Warning, err);
                            continue;
                        }

                        if (!LoadModule(fileName, (ulong)baseAddress.ToInt64(), imageSize))
                        {
                            continue;
                        }
                        m_LoadedModules[ProcessId].Add((ulong)baseAddress.ToInt64());
                    }

                    return true;
                }
                finally
                {
                    CloseHandle(handle);
                }
            });
        }
    }
}
