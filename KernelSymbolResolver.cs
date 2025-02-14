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

    internal class LoadedDriver
    {
        public string ImagePath;
        public ulong BaseAddress;
        public uint Size;
        public nint hModule;
    }

    internal class KernelSymbolResolver : ModuleResolver, IDisposable
    {
        private List<LoadedDriver> m_LoadedDrivers;
        private bool m_Disposed;

        public KernelSymbolResolver()
        {
            m_LoadedDrivers = new List<LoadedDriver>();
        }

        ~KernelSymbolResolver()
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

            foreach (var driver in m_LoadedDrivers)
            {
                FreeLibrary(driver.hModule);
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public async Task<string?> Resolve(
            ulong Address,
            SymbolFormattingOption Format,
            SymbolResolverFlags Flags
            )
        {
            string? resolved;
            if (!base.Resolve(Address, out resolved, Format, Flags) ||
                string.IsNullOrEmpty(resolved))
            {
                return null;
            }
            return resolved;
        }

        public async Task<bool> Preload()
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
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, "Out of memory");
                return false;
            }

            var status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemModuleInformation,
                buffer, (uint)size, out uint _);
            if (status != 0)
            {
                Marshal.FreeHGlobal(buffer);
                var err = $"ZwQuerySystemInformation failed: 0x{status:X}";
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                return false;
            }
            var numModules = Marshal.ReadInt32(buffer);
            if (numModules == 0)
            {
                Marshal.FreeHGlobal(buffer);
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, "No drivers found");
                return false;
            }

            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"There are {numModules} kernel modules");

            return await Task.Run(() =>
            {
                try
                {
                    var pointer = nint.Add(buffer, 8); // aligned on 8-byte boundary
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
                                  $"Skipping virtual dump driver at load address " +
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
                            return false;
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
                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            });
        }

        public async Task<bool> Load()
        {
            if (m_LoadedDrivers.Count == 0)
            {
                Debug.Assert(false);
                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Error,
                      $"Unable to load kernel resolver: no drivers found");
                return false;
            }

            return await Task.Run(() =>
            {
                foreach (var driver in m_LoadedDrivers)
                {
                    if (!LoadModule(driver.ImagePath, driver.BaseAddress, driver.Size))
                    {
                        return false;
                    }
                }
                return true;
            });
        }
    }
}
