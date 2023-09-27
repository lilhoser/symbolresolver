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
using System.Runtime.InteropServices;
using System.Text;

namespace symbolresolver
{
    internal class NativeDefinitions
    {
        public static uint SYMOPT_CASE_INSENSITIVE = 0x00000001;
        public static uint SYMOPT_UNDNAME = 0x00000002;
        public static uint SYMOPT_DEFERRED_LOADS = 0x00000004;
        public static uint SSYMOPT_INCLUDE_32BIT_MODULES = 0x00002000;
        public static uint SYMOPT_NO_PROMPTS = 0x00080000;
        public static uint SYMOPT_DEBUG = 0x80000000;
        public static uint MAX_SYM_NAME = 2000;
        public const int MAX_PATH = 260;

        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool SymbolRegisteredCallback(
            nint hProcess,
            DbgHelpCallbackActionCode ActionCode,
            nint CallbackData,
            nint UserContext
            );

        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool SymbolEnumerateModulesCallback(
            string ModuleName,
            uint DllBase,
            nint UserContext
            );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
        public struct SYMBOL_INFO
        {
            public uint SizeOfStruct;
            public uint TypeIndex;
            public ulong Reserved;
            public ulong Reserved2;
            public uint Index;
            public uint Size;
            public ulong ModBase;
            public uint Flags;
            public ulong Value;
            public ulong Address;
            public uint Register;
            public uint Scope;
            public uint Tag;
            public uint NameLen;
            public uint MaxNameLen;
            public ushort Dummy; // variable-length array of wchar follows
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
        public struct IMAGEHLP_DEFERRED_SYMBOL_LOAD
        {
            public uint SizeOfStruct;
            public ulong BaseOfImage;
            public uint Checksum;
            public uint TimeDateStamp;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH + 1)]
            public string FileName;
            [MarshalAs(UnmanagedType.U1)]
            public bool Reparse;
            public nint hFile;
            public uint Flags;
        }

        public enum SYM_TYPE
        {
            SymNone = 0,
            SymCoff,
            SymCv,
            SymPdb,
            SymExport,
            SymDeferred,
            SymSym,
            SymDia,
            SymVirtual,
            NumSymTypes
        }

        public enum DbgHelpCallbackActionCode : uint
        {
            CBA_DEFERRED_SYMBOL_LOAD_START = 0x00000001,
            CBA_DEFERRED_SYMBOL_LOAD_COMPLETE = 0x00000002,
            CBA_DEFERRED_SYMBOL_LOAD_FAILURE = 0x00000003,
            CBA_SYMBOLS_UNLOADED = 0x00000004,
            CBA_DUPLICATE_SYMBOL = 0x00000005,
            CBA_READ_MEMORY = 0x00000006,
            CBA_DEFERRED_SYMBOL_LOAD_CANCEL = 0x00000007,
            CBA_SET_OPTIONS = 0x00000008,
            CBA_EVENT = 0x00000010,
            CBA_DEFERRED_SYMBOL_LOAD_PARTIAL = 0x00000020,
            CBA_DEBUG_INFO = 0x10000000,
            CBA_SRCSRV_INFO = 0x20000000,
            CBA_SRCSRV_EVENT = 0x40000000,
            CBA_UPDATE_STATUS_BAR = 0x50000000,
            CBA_ENGINE_PRESENT = 0x60000000,
            CBA_CHECK_ENGOPT_DISALLOW_NETWORK_PATHS = 0x70000000,
            CBA_CHECK_ARM_MACHINE_THUMB_TYPE_OVERRIDE = 0x80000000,
            CBA_XML_LOG = 0x90000000,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct IMAGEHLP_MODULE64
        {
            public uint SizeOfStruct;
            public long BaseOfImage;
            public int ImageSize;
            public int TimeDateStamp;
            public int CheckSum;
            public int NumSyms;
            public SYM_TYPE SymType;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string ModuleName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ImageName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string LoadedImageName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string LoadedPdbName;
            public int CVSig;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260 * 3)]
            public string CVData;
            public int PdbSig;
            public Guid PdbSig70;
            public int PdbAge;
            [MarshalAs(UnmanagedType.Bool)]
            public bool PdbUnmatched;
            [MarshalAs(UnmanagedType.Bool)]
            public bool DbgUnmatched;
            [MarshalAs(UnmanagedType.Bool)]
            public bool LineNumbers;
            [MarshalAs(UnmanagedType.Bool)]
            public bool GlobalSymbols;
            [MarshalAs(UnmanagedType.Bool)]
            public bool TypeInfo;
            [MarshalAs(UnmanagedType.Bool)]
            public bool SourceIndexed;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Publics;
            public int MachineType;
            public int Reserved;
        }

        [DllImport("dbghelp.dll", EntryPoint="SymInitializeW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymInitialize(
            nint hProcess,
            [In()][MarshalAs(UnmanagedType.LPStr)] string UserSearchPath,
            [MarshalAs(UnmanagedType.Bool)] bool fInvadeProcess
            );

        [DllImport("dbghelp.dll", EntryPoint="SymFromAddrW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymFromAddr(
            nint hProcess,
            ulong Address,
            ref ulong Displacement,
            nint Symbol
            );

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint SymSetOptions(uint SymOptions);

        [DllImport("dbghelp.dll", EntryPoint = "SymLoadModuleExW", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern nint SymLoadModuleEx(
            nint hProcess,
            nint hFile,
            string ImageName,
            string ModuleName,
            ulong BaseOfDll,
            uint DllSize,
            nint Data,
            uint Flags);

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymUnloadModule64(
            nint hProcess,
            ulong BaseOfDll
            );

        [DllImport("dbghelp.dll", EntryPoint = "SymEnumerateModulesW64", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymEnumerateModules(
            nint hProcess,
            SymbolEnumerateModulesCallback Callback,
            nint UserContext
            );

        [DllImport("dbghelp.dll", EntryPoint = "SymGetModuleInfoW64", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymGetModuleInfo(
            nint hProcess,
            ulong Address,
            nint ModuleInfo
            );

        [DllImport("dbghelp.dll", EntryPoint="SymRegisterCallbackW64", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymRegisterCallback64(
            nint hProcess,
            SymbolRegisteredCallback Callback,
            nint UserContext
            );

        [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SymCleanup(nint hProcess);

        //
        // Kernel32
        //
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static public extern bool SetDllDirectory(string lpPathName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern nint OpenProcess(
            uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(nint hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process(
            nint hProcess,
            [Out][MarshalAs(UnmanagedType.Bool)] out bool Wow64Process);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static public extern nint LoadLibraryEx(
            [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
            nint hFile,
            uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(nint hModule);

        public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const uint SYNCHRONIZE = 0x00100000;
        public const uint PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF;
        public const uint LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040;
        public const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020;

        //
        // Psapi
        //
        [Flags]
        public enum EnumProcessModulesFilter
        {
            LIST_MODULES_DEFAULT = 0x00,
            LIST_MODULES_32BIT = 0x01,
            LIST_MODULES_64BIT = 0x02,
            LIST_MODULES_ALL = LIST_MODULES_32BIT | LIST_MODULES_64BIT,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct MODULE_INFO
        {
            public nint BaseOfDll;
            public uint SizeOfImage;
            public nint EntryPoint;
        }

        [DllImport("Psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumProcessModulesEx(
              nint hProcess,
              [Out] nint[] lphModule,
              int cb,
              out int lpcbNeeded,
              EnumProcessModulesFilter dwFilterFlag
            );

        [DllImport("Psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumDeviceDrivers(
              [Out] nint[] lpImageBase,
              int cb,
              out int lpcbNeeded
            );

        [DllImport("Psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetModuleInformation(
              nint hProcess,
              nint hModule,
              nint lpModInfo,
              uint cb);

        [DllImport("Psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetModuleFileNameEx(
              nint hProcess,
              nint hModule,
              nint lpFilename,
              int nSize);

        [DllImport("Psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetDeviceDriverFileName(
              nint ImageBase,
              nint lpFilename,
              int nSize);

        //
        // ntdll
        //
        public enum SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation,
            SystemProcessorInformation,
            SystemPerformanceInformation,
            SystemTimeOfDayInformation,
            SystemPathInformation,
            SystemProcessInformation,
            SystemCallCountInformation,
            SystemDeviceInformation,
            SystemProcessorPerformanceInformation,
            SystemFlagsInformation,
            SystemCallTimeInformation,
            SystemModuleInformation,
            SystemLocksInformation,
            SystemStackTraceInformation,
            SystemPagedPoolInformation,
            SystemNonPagedPoolInformation,
            SystemHandleInformation,
            SystemObjectInformation,
            SystemPageFileInformation,
            SystemVdmInstemulInformation,
            SystemVdmBopInformation,
            SystemFileCacheInformation,
            SystemPoolTagInformation,
            SystemInterruptInformation,
            SystemDpcBehaviorInformation,
            SystemFullMemoryInformation,
            SystemLoadGdiDriverInformation,
            SystemUnloadGdiDriverInformation,
            SystemTimeAdjustmentInformation,
            SystemSummaryMemoryInformation,
            SystemNextEventIdInformation,
            SystemEventIdsInformation,
            SystemCrashDumpInformation,
            SystemExceptionInformation,
            SystemCrashDumpStateInformation,
            SystemKernelDebuggerInformation,
            SystemContextSwitchInformation,
            SystemRegistryQuotaInformation,
            SystemExtendServiceTableInformation,
            SystemPrioritySeperation,
            SystemPlugPlayBusInformation,
            SystemDockInformation,
            SystemPowerInformation,
            SystemProcessorSpeedInformation,
            SystemCurrentTimeZoneInformation,
            SystemLookasideInformation,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 8)]
        public struct SYSTEM_MODULE_INFORMATION
        {
            public nint Section;
            public nint MappedBase;
            public nint ImageBase;
            public uint Size;
            public uint Flags;
            public ushort LoadOrderIndex;
            public ushort InitOrderIndex;
            public ushort LoadCount;
            public ushort ModuleNameOffset;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ImageName;
        }

        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern uint ZwQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            nint SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);
    }
}
