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

    internal class CachedSymbol
    {
        public CachedSymbol(ulong address, string resolved)
        {
            Address = address;
            ResolvedSymbol = resolved;
        }
        public ulong Address;
        public string ResolvedSymbol;
    }

    public class SymbolResolver : IDisposable
    {
        private nint m_SymHandle; // NOT a process handle!
        private string m_DebuggerToolsPath;
        private string m_SymbolPath;
        private Dictionary<int, List<CachedSymbol>> m_SymbolCache;
        private bool m_Disposed;
        private KernelSymbolResolver m_KernelResolver;
        private UserSymbolResolver m_UserResolver;

        public
        SymbolResolver(string SymbolPath, string DebuggerToolsPath)
        {
            m_SymbolPath = SymbolPath;
            m_SymbolCache = new Dictionary<int, List<CachedSymbol>>();
            m_DebuggerToolsPath = DebuggerToolsPath;
            m_KernelResolver = new KernelSymbolResolver();
            m_UserResolver = new UserSymbolResolver();
            m_SymHandle = nint.Zero;
        }

        ~SymbolResolver()
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

            if (m_SymHandle != nint.Zero)
            {
                Debug.Assert(SymCleanup(m_SymHandle));
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public async Task<bool> Initialize()
        {
            if (m_SymHandle != nint.Zero)
            {
                Debug.Assert(false);
                return true;
            }

            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"Initializing symbol resolver");

            //
            // Load driver modules using LoadLibraryEx to force sym API to recognize it.
            //
            if (!await m_KernelResolver.Preload())
            {
                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Error,
                      $"Failed to pre-initialize kernel resolver");
                return false;
            }

            //
            // Use dbghelp.dll and friends from debugger tools
            //
            if (!SetDllDirectory(m_DebuggerToolsPath))
            {
                var err = $"Unable to set dll directory: 0x{Marshal.GetLastWin32Error():X}";
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                return false;
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
                var err = $"SymSetOptions failed: 0x{Marshal.GetLastWin32Error():X}";
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                return false;
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
                var err = $"SymInitialize failed: 0x{Marshal.GetLastWin32Error():X}";
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                return false;
            }

            Trace(TraceLoggerType.Resolver, TraceEventType.Information, $"SymInitialize complete");

            m_KernelResolver.SetSymHandle(m_SymHandle);
            m_UserResolver.SetSymHandle(m_SymHandle);

            //
            // Now SymLoadModuleEx on kernel modules. This only needs to be done once,
            // as opposed to user modules that are per-process.
            //
            if (!await m_KernelResolver.Load())
            {
                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Error,
                      $"Failed to initialize kernel resolver");
                return false;
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

                    Trace(TraceLoggerType.Dbghelp, TraceEventType.Information, message);
                    return true;
                },
                nint.Zero))
            {
                Trace(TraceLoggerType.Resolver,
                      TraceEventType.Error,
                      $"SymRegisterCallback64 failed: 0x{Marshal.GetLastWin32Error():X}");
            }
            return true;
        }

        public async Task<string?> ResolveUserAddress(
            int ProcessId,
            ulong Address, 
            SymbolFormattingOption Format,
            SymbolResolverFlags Flags = SymbolResolverFlags.None
            )
        {
            if (m_SymHandle == nint.Zero)
            {
                Debug.Assert(false);
                return null;
            }

            if (m_SymbolCache.ContainsKey(ProcessId))
            {
                var match = m_SymbolCache[ProcessId].FirstOrDefault(s => s.Address == Address);
                if (match != default)
                {
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Information,
                          $"Symbol 0x{Address:X} = {match.ResolvedSymbol} (cached)");
                    return match.ResolvedSymbol;
                }
            }
            else
            {
                m_SymbolCache.Add(ProcessId, new List<CachedSymbol>());
            }

            var resolved = await m_UserResolver.Resolve(ProcessId, Address, Format, Flags);
            if (!string.IsNullOrEmpty(resolved))
            {
                m_SymbolCache[ProcessId].Add(new CachedSymbol(Address, resolved));
            }
            return resolved;
        }

        public async Task<string?> ResolveKernelAddress(
            ulong Address,
            SymbolFormattingOption Format,
            SymbolResolverFlags Flags = SymbolResolverFlags.None
            )
        {
            if (m_SymHandle == nint.Zero)
            {
                Debug.Assert(false);
                return null;
            }

            //
            // No cache needed in front of kernel addresses, because these are one-time/global
            // addresses and symbols.
            //
            return await m_KernelResolver.Resolve(Address, Format, Flags);
        }
    }
}