# Introduction

symbolresolver is a .NET library that provides front-end access to Microsoft's debugging tools (Dbghelp.dll).

# Requirements
* Windows 10+ or later operating system with debugging tools installed
* .NET 9+ runtime
* Some features require administrator privileges

# Using symbolresolver

* Add the symbolresolver nuget package to your project using the Nuget package manager.
* Reference the namespace: `using symbolresolver`

To use symbolresolver, you will need to specify the path to dbghelp.dll (installed alongside Microsoft's debugging tools) and your desired symbol path. Here is an example:

```
var dbghelp = @"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll";
var symbolPath = @"srv*c:\symbols*https://msdl.microsoft.com/download/symbols";
```

Resolving a user-mode address to a symbol requires loading that process's modules into the symbol engine:

```
try
{
    var pid = 1026;
    var address = 0x71230010;
    var resolver = new SymbolResolver(s_SymbolPath, s_DbgHelpLocation);
    if (await resolver.Initialize())
    {
        var resolved = await resolver.ResolveUserAddress(
            pid, address, SymbolFormattingOption.SymbolAndModule);
    }
}
catch (Exception ex)
{
    ...
}
```

If this is successful (careful with permissions), you can retrieve the symbol name of any arbitrary address:

```
var symbol = resolver.GetFormattedSymbol(address);
```

The process is identical for kernel-mode addresses, except that you do not need to provide a PID.

The format of the resolved symbol returned by the `Resolve***` APIs can be adjusted by passing an option enum:
* `SymbolOnly`: If a named symbol is found at the given address, the name will be returned. For example, `NtOpenProcess`. If there is no named symbol at the given address, the returned string will be formatted as `<unknown_0x71230010>`.
* `SymbolAndModule`: The module name, if found, will be prepended to the returned string in the format `<module>!<symbol>`. For example, `ntdll!NtOpenTrace`. If the module name cannot be retrieved, the module name portion of the returned string will be formatted as `<unknown_module>`.

By default, except in cases of critical errors, `Resolve***` APIs will always return a value, even if there is no named symbol at a given address, as discussed above. This behavior can be overridden by passing the flag `FailIfNoSymbolFound`, in which case no resolved string will be returned if there is no named symbol at a given address.


# Caveats
* Be careful running the library under Visual Studio, which also uses Dbghelp.dll
