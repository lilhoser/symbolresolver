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
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace symbolresolver
{
    using static TraceLogger;
    using static NativeDefinitions;

    public enum SymbolFormattingOption
    {
        SymbolOnly,
        SymbolAndModule
    }

    [Flags]
    public enum SymbolResolverFlags
    {
        None,
        FailIfNoSymbolFound // if not set, resolved symbol will be returned as unknown_0x<address>
    }

    internal abstract class ModuleResolver
    {
        protected nint m_SymHandle;

        protected ModuleResolver()
        {
        }

        public void SetSymHandle(nint SymHandle)
        {
            m_SymHandle = SymHandle;
        }

        protected bool LoadModule(string Path, ulong Base, uint Size)
        {
            if (m_SymHandle == nint.Zero)
            {
                Debug.Assert(false);
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, "ModuleResolver is not initialized");
                return false;
            }

            Trace(TraceLoggerType.Resolver,
                  TraceEventType.Information,
                  $"Loading module {Path} (Base=0x{Base:X}, size={Size})");

            var baseAddress = SymLoadModuleEx(m_SymHandle, nint.Zero, Path, null, Base, Size, nint.Zero, 0);
            if (baseAddress == 0)
            {
                var code = Marshal.GetLastWin32Error();
                if (code != 0)
                {
                    var err = $"SymLoadModuleEx failed: 0x{code:X}";
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Error,
                          err);
                    return false;
                }
                //
                // Module was already loaded.
                //
                return true;
            }

            //
            // Since we have deferred symbol load option set, force load now by referencing a symbol.
            //
            var info = new IMAGEHLP_MODULE64();
            if (!GetModuleInfo(Base + 1, ref info) || (string.IsNullOrEmpty(info.ModuleName)))
            {
                var err = $"Unable to resolve address 0x{(Base + 1):X} in module";
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, err);
                return false;
            }
            return true;
        }

        protected bool Resolve(
            ulong Address,
            out string? ResolvedSymbol,
            SymbolFormattingOption Format,
            SymbolResolverFlags Flags
            )
        {
            ResolvedSymbol = null;
            if (m_SymHandle == nint.Zero)
            {
                Debug.Assert(false);
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, "ModuleResolver is not initialized");
                return false;
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
                    Trace(TraceLoggerType.Resolver, TraceEventType.Error, "Out of memory");
                    return false;
                }

                Marshal.StructureToPtr(symbol, buffer, false);

                if (!SymFromAddr(m_SymHandle, Address, ref displacement, buffer))
                {
                    var code = Marshal.GetLastWin32Error();
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Error,
                          $"Unable to resolve symbol at address 0x{Address:X}: 0x{code:X}");
                    if (Flags.HasFlag(SymbolResolverFlags.FailIfNoSymbolFound))
                    {
                        return false;
                    }
                }
                else
                {
                    symbol = (SYMBOL_INFO)Marshal.PtrToStructure(buffer, typeof(SYMBOL_INFO))!;
                    var nameLenCharacters = (int)symbol.NameLen; // not incl. null-term
                    if (nameLenCharacters == 0)
                    {
                        Trace(TraceLoggerType.Resolver,
                              TraceEventType.Error,
                              $"Symbol name length was 0");
                        return false;
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
            }
            finally
            {
                if (buffer != nint.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            if (resolved == null)
            {
                resolved = $"<unknown_0x{Address:X}>";
            }

            if (Format == SymbolFormattingOption.SymbolAndModule)
            {
                string moduleName = "<unknown_module>";
                var info = new IMAGEHLP_MODULE64();
                if (GetModuleInfo(Address, ref info) && (!string.IsNullOrEmpty(info.ModuleName)))
                {
                    moduleName = info.ModuleName;
                }
                resolved = $"{moduleName}!{resolved}";
            }

            ResolvedSymbol = resolved;
            return true;
        }

        private bool GetModuleInfo(ulong Address, ref IMAGEHLP_MODULE64 Info)
        {
            if (m_SymHandle == nint.Zero)
            {
                Debug.Assert(false);
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, "ModuleResolver is not initialized");
                return false;
            }

            Info.SizeOfStruct = (uint)Marshal.SizeOf(typeof(IMAGEHLP_MODULE64));
            var buffer = Marshal.AllocHGlobal((int)(Info.SizeOfStruct));
            if (buffer == nint.Zero)
            {
                Trace(TraceLoggerType.Resolver, TraceEventType.Error, "Out of memory");
                return false;
            }

            try
            {
                Marshal.StructureToPtr(Info, buffer, false);
                if (!SymGetModuleInfo(m_SymHandle, Address, buffer))
                {
                    //
                    // Similar to SymFromAddr, this API can fail for a host of reasons.
                    //
                    var err = $"SymGetModuleInfo failed: 0x{Marshal.GetLastWin32Error():X}";
                    Trace(TraceLoggerType.Resolver,
                          TraceEventType.Error,
                          err);
                    return false;
                }
                Info = (IMAGEHLP_MODULE64)Marshal.PtrToStructure(buffer, typeof(IMAGEHLP_MODULE64))!;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return true;
        }
    }
}
