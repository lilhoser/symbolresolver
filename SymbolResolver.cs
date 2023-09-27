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
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace symbolresolver
{
    using static NativeDefinitions;
    using static TraceLogger;

    public class SymbolResolver
    {
        private nint m_SymHandle; // NOT a process handle!
        private string m_DebuggerToolsPath;
        private string m_SymbolPath;
        private Dictionary<ulong, string> m_SymbolCache;
        private List<ulong> m_LoadedModules;
        private List<LoadedDriver> m_LoadedDrivers;

        public class LoadedDriver
        {
            public string ImagePath;
            public ulong BaseAddress;
            public uint Size;
            public nint hModule;
        }

        public
        SymbolResolver(string SymbolPath, string DebuggerToolsPath)
        {
            m_SymbolPath = SymbolPath;
            m_SymbolCache = new Dictionary<ulong, string>();
            m_DebuggerToolsPath = DebuggerToolsPath;
            m_LoadedModules = new List<ulong>();
            m_LoadedDrivers = new List<LoadedDriver>();
        }

        ~SymbolResolver()
        {
            Trace(TraceLoggerType.Resolver,
                 TraceEventType.Verbose,
                  "Entered destructor");
            foreach (var module in m_LoadedModules)
            {
                SymUnloadModule64(m_SymHandle, module);
            }

            foreach (var driver in m_LoadedDrivers)
            {
                FreeLibrary(driver.hModule);
            }

            if (m_SymHandle != nint.Zero)
            {
                Debug.Assert(SymCleanup(m_SymHandle));
            }
        }

        public
        void
        Initialize()
        {
            if (m_SymHandle != nint.Zero)
            {
                return;
            }

            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"Initializing resolver");

            //
            // Preload driver modules using LoadLibraryEx to force sym API to recognize it.
            //
            LoadAllKernelModules();

            //
            // Use dbghelp.dll and friends from debugger tools
            //
            if (!SetDllDirectory(m_DebuggerToolsPath))
            {
                var err = $"Unable to set dll directory: " +
                    $"{Marshal.GetLastWin32Error():X}";
                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Error,
                      err);
                throw new Exception(err);
            }

            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"Dll search path set to {m_DebuggerToolsPath}");

            uint flags = SYMOPT_UNDNAME |
                         SYMOPT_DEBUG |
                         SYMOPT_NO_PROMPTS |
                         SYMOPT_CASE_INSENSITIVE |
                         SYMOPT_DEFERRED_LOADS |
                         SSYMOPT_INCLUDE_32BIT_MODULES;

            if (SymSetOptions(flags) != flags)
            {
                var err = $"SymSetOptions failed:  " +
                    $"0x{Marshal.GetLastWin32Error():X}";
                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Error,
                      err);
                throw new Exception(err);
            }

            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"Sym options set to  0x{flags:X}");

            //
            // See MSDN for the hProcess argument to SymInitialize. It just needs to be
            // a unique number. It seems to have nothing to do with a process at all.
            //
            var r = new Random();
            m_SymHandle = new nint(r.NextInt64());
            if (!SymInitialize(m_SymHandle, m_SymbolPath, false))
            {
                    var err = $"SymInitialize failed:  " +
                        $"0x{Marshal.GetLastWin32Error():X}";
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Error,
                          err);
                    throw new Exception(err);
            }

            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"SymInitialize complete");

            //
            // Now SymLoadModuleEx on kernel modules.
            //
            foreach (var driver in m_LoadedDrivers)
            {
                LoadModule(driver.ImagePath, driver.BaseAddress, driver.Size);
            }

            //
            // Log all sym noisy events to trace session
            //
            if (!SymRegisterCallback64(
                m_SymHandle,
                (process, action, data, context) =>
                {
                    var message = "DBGHELP: ";
                    switch (action)
                    {
                        case DbgHelpCallbackActionCode.CBA_SYMBOLS_UNLOADED:
                            {
                                message += "Symbols unloaded";
                                break;
                            }
                        case DbgHelpCallbackActionCode.CBA_DEBUG_INFO:
                            {
                                message += Marshal.PtrToStringUni(data);
                                break;
                            }
                        case DbgHelpCallbackActionCode.CBA_DEFERRED_SYMBOL_LOAD_COMPLETE:
                            {
                                var info = (IMAGEHLP_DEFERRED_SYMBOL_LOAD)Marshal.PtrToStructure(
                                    data, typeof(IMAGEHLP_DEFERRED_SYMBOL_LOAD))!;
                                message += $"Symbols loaded for {info.FileName} " +
                                    $"(Checksum=0x{info.Checksum:X})" +
                                    $": Base=0x{info.BaseOfImage:X}, Flags=0x{info.Flags:X}";
                                break;
                            }
                        case DbgHelpCallbackActionCode.CBA_DEFERRED_SYMBOL_LOAD_FAILURE:
                            {
                                var info = (IMAGEHLP_DEFERRED_SYMBOL_LOAD)Marshal.PtrToStructure(
                                    data, typeof(IMAGEHLP_DEFERRED_SYMBOL_LOAD))!;
                                message += $"Symbol load failed for {info.FileName} " +
                                    $"(Checksum=0x{info.Checksum:X})" +
                                    $": Base=0x{info.BaseOfImage:X}, Flags=0x{info.Flags:X}";
                                break;
                            }
                        default:
                            {
                                return false;
                            }
                    }

                    Trace(TraceLoggerType.Dbghelp,
                            TraceEventType.Information,
                            message);
                    return true;
                },
                nint.Zero))
            {
                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Error,
                      $"SymRegisterCallback64 failed: 0x{Marshal.GetLastWin32Error():X}");
            }
        }

        public
        void
        InitializeForProcess(int ProcessId)
        {
            if (m_SymHandle == nint.Zero)
            {
                throw new Exception("SymbolResolver is not initialized");
            }
            LoadAllUserModules(ProcessId);
        }

        public
        string?
        GetFormattedSymbol(ulong Address)
        {
            if (m_SymHandle == nint.Zero)
            {
                throw new Exception("SymbolResolver is not initialized");
            }

            var moduleInfo = GetModuleInfo(Address);
            string moduleName = "<unknown_module>";
            if (!string.IsNullOrEmpty(moduleInfo.ModuleName))
            {
                moduleName = moduleInfo.ModuleName;
            }

            var formatted = moduleName;
            var symbol = SymbolFromAddress(Address);

            if (!string.IsNullOrEmpty(symbol))
            {
                formatted += $"!{symbol}";
            }
            else
            {
                formatted += $"!<unknown_0x{Address:X}>";
            }

            return formatted;
        }

        public
        string?
        SymbolFromAddress(
            ulong Address
            )
        {
            if (m_SymHandle == nint.Zero)
            {
                throw new Exception("SymbolResolver is not initialized");
            }

            if (m_SymbolCache.ContainsKey(Address))
            {
                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Information,
                      $"Symbol 0x{Address:X} = {m_SymbolCache[Address]} (cached)");
                return m_SymbolCache[Address];
            }

            nint buffer = nint.Zero;
            string? resolved = null;

            try
            {
                ulong displacement = 0;
                var symbol = new SYMBOL_INFO();
                symbol.MaxNameLen = MAX_SYM_NAME;
                symbol.SizeOfStruct = (uint)Marshal.SizeOf(typeof(SYMBOL_INFO));
                buffer = Marshal.AllocHGlobal((int)(symbol.SizeOfStruct + MAX_SYM_NAME));
                if (buffer == nint.Zero)
                {
                    throw new Exception("Out of memory");
                }

                Marshal.StructureToPtr(symbol, buffer, false);

                if (!SymFromAddr(m_SymHandle, Address, ref displacement, buffer))
                {
                    var code = Marshal.GetLastWin32Error();
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Warning,
                          $"Unable to resolve symbol at address 0x{Address:X}: 0x{code:X}");
                    //
                    // This might not be catastrophic, so don't throw an exception
                    //
                    return null;
                }

                symbol = (SYMBOL_INFO)Marshal.PtrToStructure(buffer, typeof(SYMBOL_INFO))!;
                var nameLenCharacters = (int)symbol.NameLen; // not incl. null-term

                if (nameLenCharacters == 0)
                {
                    throw new Exception("Symbol name length was 0!");
                }

                //
                // Marshal the name buffer, which is just after the last field in SYMBOL_INFO.
                // TODO: Add in displacement, if available.
                //
                var nameLenBytes = nameLenCharacters * 2; // Unicode
                byte[] nameData = new byte[nameLenBytes];
                var pointer = nint.Add(buffer, (int)Marshal.OffsetOf<SYMBOL_INFO>("Dummy"));
                Marshal.Copy(pointer, nameData, 0, nameLenBytes);
                resolved = Encoding.Unicode.GetString(nameData, 0, nameLenBytes);

                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Information,
                      $"Symbol 0x{Address:X} = {resolved}");
            }
            finally
            {
                if (buffer != nint.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            if (!string.IsNullOrEmpty(resolved))
            {
                m_SymbolCache.Add(Address, resolved);
            }

            return resolved;
        }

        public
        List<LoadedDriver>
        GetLoadedKernelDrivers()
        {
            return m_LoadedDrivers;
        }

        private
        IMAGEHLP_MODULE64
        GetModuleInfo(ulong Address)
        {
            if (m_SymHandle == nint.Zero)
            {
                throw new Exception("SymbolResolver is not initialized");
            }

            var moduleInfo = new IMAGEHLP_MODULE64();
            moduleInfo.SizeOfStruct = (uint)Marshal.SizeOf(typeof(IMAGEHLP_MODULE64));
            var buffer = Marshal.AllocHGlobal((int)(moduleInfo.SizeOfStruct));
            if (buffer == nint.Zero)
            {
                throw new Exception("Out of memory");
            }

            try
            {
                Marshal.StructureToPtr(moduleInfo, buffer, false);

                if (!SymGetModuleInfo(m_SymHandle, Address, buffer))
                {
                    //
                    // Similar to SymFromAddr, this API can fail for a host of reasons.
                    // We'll trace an error, but no exception.
                    //
                    var err = $"SymGetModuleInfo failed: 0x{Marshal.GetLastWin32Error():X}";
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Error,
                          err);
                    return moduleInfo;
                }

                moduleInfo = (IMAGEHLP_MODULE64)Marshal.PtrToStructure(
                    buffer, typeof(IMAGEHLP_MODULE64))!;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return moduleInfo;
        }

        private
        void
        LoadAllUserModules(int ProcessId)
        {
            if (m_SymHandle == nint.Zero)
            {
                throw new Exception("SymbolResolver is not initialized");
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
                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Error,
                      err);
                throw new Exception(err);
            }

            if (ProcessId == nint.Zero)
            {
                var code = Marshal.GetLastWin32Error();
                if (code == 0x5)
                {
                    //
                    // Wrap this up separately so caller can handle it explicitly if desired.
                    //
                    var err = $"Unable to open process ID {ProcessId}: access is denied";
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Error,
                          err);
                    throw new AccessViolationException(err);
                }
                else if (code == 0x57)
                {
                    //
                    // The process likely isn't running - this can happen if the source
                    // of our requestor is from an ETW containing a PID from a terminated
                    // process, as an example.
                    //
                    throw new InvalidOperationException($"Process {ProcessId} doesn't exist");
                }
                else
                {
                    var err = $"Unable to open process ID {ProcessId}:  0x{code:X}";
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Error,
                          err);
                    throw new Exception(err);
                }
            }

            try
            {
                //
                // Enumerate all modules in this process
                //
                if (!IsWow64Process(handle, out bool isWow64))
                {
                    var err = $"IsWow64Process failed:  " +
                        $"0x{Marshal.GetLastWin32Error():X}";
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Error,
                          err);
                    throw new Exception(err);
                }

                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Information,
                      $"Enumerating modules for process");

                var modules = new nint[1024];
                var size = modules.Length * nint.Size;
                var modFilter = isWow64 ? EnumProcessModulesFilter.LIST_MODULES_32BIT : EnumProcessModulesFilter.LIST_MODULES_64BIT;

                if (!EnumProcessModulesEx(handle, modules, size, out int numModules, modFilter))
                {
                    var err = $"EnumProcessModulesEx failed:  " +
                        $"0x{Marshal.GetLastWin32Error():X}";
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Error,
                          err);
                    throw new Exception(err);
                }

                if (numModules == 0)
                {
                    //
                    // Likely a frozen/suspended UWP process.
                    //
                    throw new InvalidOperationException($"Process {ProcessId} has no loaded modules");
                }

                foreach (var module in modules.Take(numModules / nint.Size))
                {
                    var buffer = Marshal.AllocHGlobal(1024);
                    if (buffer == nint.Zero)
                    {
                        throw new Exception("Out of memory");
                    }

                    var fileNameSize = GetModuleFileNameEx(handle, module, buffer, 1024);
                    if (fileNameSize == 0)
                    {
                        Marshal.FreeHGlobal(buffer);
                        var err = $"GetModuleFileNameEx failed:  " +
                            $"0x{Marshal.GetLastWin32Error():X}";
                        Trace(TraceLoggerType.Resolver,
                              TraceEventType.Error,
                              err);
                        throw new Exception(err);
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
                        throw new Exception("Out of memory");
                    }

                    if (!GetModuleInformation(handle, module, buffer, (uint)size))
                    {
                        Marshal.FreeHGlobal(buffer);
                        var err = $"GetModuleInformation failed for {fileName}:  " +
                            $"0x{Marshal.GetLastWin32Error():X}";
                        Trace(TraceLoggerType.Resolver,
                              TraceEventType.Error,
                              err);
                        throw new Exception(err);
                    }

                    var modInfo = (MODULE_INFO)Marshal.PtrToStructure(
                        buffer, typeof(MODULE_INFO))!;
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
                        Trace(TraceLoggerType.Resolver,
                              TraceEventType.Error,
                              err);
                        continue;
                    }

                    LoadModule(fileName, (ulong)baseAddress.ToInt64(), imageSize);
                    m_LoadedModules.Add((ulong)baseAddress.ToInt64());
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        private
        void
        LoadAllKernelModules()
        {
            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"Loading all kernel modules");

            var result = IsWow64Process(Process.GetCurrentProcess().Handle, out bool isWow64);
            Debug.Assert(result && !isWow64);

            //
            // Use Zw API to get full driver information including base and size.
            // For simplicity, we'll allocate a large enough buffer for 1024 drivers.
            //
            var size = Marshal.SizeOf(typeof(SYSTEM_MODULE_INFORMATION)) * 1024;
            var buffer = Marshal.AllocHGlobal(size);
            if (buffer == nint.Zero)
            {
                throw new Exception("Out of memory");
            }

            var status = ZwQuerySystemInformation(
                SYSTEM_INFORMATION_CLASS.SystemModuleInformation,
                buffer,
                (uint)size,
                out uint _);
            if (status != 0)
            {
                Marshal.FreeHGlobal(buffer);
                throw new Exception($"ZwQuerySystemInformation failed: 0x{status:X}");
            }
            var numModules = Marshal.ReadInt32(buffer);
            if (numModules == 0)
            {
                Marshal.FreeHGlobal(buffer);
                throw new Exception("No driver modules found.");
            }

            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"There are {numModules} kernel modules");

            var pointer = nint.Add(buffer, 8); // aligned on 8-byte boundary

            try
            {
                for (int i = 0; i < numModules; i++)
                {
                    var module = (SYSTEM_MODULE_INFORMATION)Marshal.PtrToStructure(
                        pointer, typeof(SYSTEM_MODULE_INFORMATION))!;
                    if (string.IsNullOrEmpty(module.ImageName))
                    {
                        Trace(TraceLoggerType.Resolver,
                              TraceEventType.Warning,
                              $"Skipping unnamed module at load address 0x{module.ImageBase:X}");
                        continue;
                    }

                    //
                    // Normalize driver path
                    //
                    var driverPath = module.ImageName.ToLower();

                    if (driverPath.StartsWith(@"\systemroot\"))
                    {
                        driverPath = driverPath.Replace(@"\systemroot",
                            Environment.GetEnvironmentVariable("SystemRoot"));
                    }
                    else if (driverPath.StartsWith(@"\??\"))
                    {
                        driverPath = driverPath.Remove(0, 4);
                    }

                    var driverName = Path.GetFileName(driverPath);
                    if (driverName.StartsWith("dump_"))
                    {
                        //
                        // These don't really exist on disk.
                        //
                        Trace(TraceLoggerType.Resolver,
                              TraceEventType.Information,
                              $"Skipping virtual dump driver at load address "+
                              $"0x{module.ImageBase:X}");
                        continue;
                    }

                    Debug.Assert(File.Exists(driverPath));

                    //
                    // Important: We use LoadLibraryEx ourselves instead of calling
                    // SymLoadModuleEx, which doesn't appear to work.
                    //
                    var handle = LoadLibraryEx(driverPath,
                        nint.Zero,
                        LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE);
                    if (handle == nint.Zero)
                    {
                        var err = $"LoadLibraryEx failed: 0x{Marshal.GetLastWin32Error():X}";
                        Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                        throw new Exception(err);
                    }

                    m_LoadedDrivers.Add(new LoadedDriver
                    {
                        hModule = handle,
                        ImagePath = driverPath,
                        BaseAddress = (ulong)module.ImageBase.ToInt64(),
                        Size = module.Size
                    });

                    pointer = nint.Add(pointer,
                        Marshal.SizeOf(typeof(SYSTEM_MODULE_INFORMATION)));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private
        void
        LoadModule(string Path, ulong Base, uint Size)
        {
            if (m_SymHandle == nint.Zero)
            {
                throw new Exception("SymbolResolver is not initialized");
            }

            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"Loading module {Path} (Base=0x{Base:X}, size={Size})");

            var baseAddress = SymLoadModuleEx(m_SymHandle,
                nint.Zero,
                Path,
                null,
                Base,
                Size,
                nint.Zero,
                0);
            if (baseAddress == 0)
            {
                var code = Marshal.GetLastWin32Error();
                if (code != 0)
                {
                    var err = $"SymLoadModuleEx failed: 0x{code:X}";
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Error,
                          err);
                    throw new Exception(err);
                }

                //
                // Module was already loaded.
                //
                return;
            }

            //
            // Since we have deferred symbol load option set, force load now by
            // referencing a symbol.
            //
            var moduleInfo = GetModuleInfo(Base + 1);
            if (string.IsNullOrEmpty(moduleInfo.ModuleName))
            {
                throw new Exception($"Unable to resolve address 0x{(Base + 1):X} in module");
            }
        }
    }
}