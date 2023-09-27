# Introduction

symbolresolver is a .NET library that provides front-end access to Microsoft's debugging tools (Dbghelp.dll).

# Requirements
* Windows 10+ or later operating system with debugging tools installed
* .NET 7+ runtime
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
resolver = new SymbolResolver(symbolPath, dbghelp);
resolver.Initialize();
resolver.InitializeForProcess(pid);
```

If this is successful (careful with permissions), you can retrieve the symbol name of any arbitrary address:

```
var symbol = resolver.GetFormattedSymbol(address);
```

The process is identical for kernel-mode addresses, except that you do not need to invoke `InitializeForProcess`.

# Caveats
* Be careful running the library under Visual Studio, which also uses Dbghelp.dll
