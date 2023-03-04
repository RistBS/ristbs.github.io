---
layout:     post
title:      "Hijack Explorer Context Menu for Persistence & Fun"
date:       2023-02-15 23:17:00 +0300
---

Learn how I hijacked the explorer context menu to execute my beacon at each right click on a file/folder.

- [Introduction](#introduction)
- [What is COM ?](#what-is-com-)
- [Explorer Context Menu Hijacking](#explorer-context-menu-hijacking)
  - [`IContextMenu` & `IShellExtInit` interfaces](#icontextmenu--ishellextinit-interfaces)
  - [Shell Extension `ContextMenuHandlers`](#shell-extension-contextmenuhandlers)
  - [Put it all together](#put-it-all-together)
- [Conclusion](#conclusion)
- [Credits](#credits)

## Introduction

I get the idea to implement it and share it when I watched the video of [@ParanoidNinja](https://twitter.com/NinjaParanoid) about [Windows Context Menu (Right Click) COM Hijacking for Persistence](https://www.youtube.com/watch?v=SwdmijpSjjA&ab_channel=ChetanNayak). This is also an opportunity to talk about the COM hijacking technique if it's still not clear to you. So let's see how it works.

If you want to use it, feel free to do it and put a star :) -> [ContextMenuHijack](https://github.com/RistBS/ContextMenuHijack)


## What is COM ?

Component Object Model (COM) is **object-oriented** and an Application Binary Interface (ABI) and used in frameworks such as **IExplorer, OLE, ActiveX, COM+, DCOM, MTS, MSMQ, IIS, IPP, RPC, DTC, MMC, DirectX**. The COM architecture allows developers to create their own applications and share them with others.

When an application needs to use a COM object, it typically calls the `CoCreateInstance` function, which requests the **Services Control Manager (SCM)** to query registry keys like `HKEY_LOCAL_MACHINE` (HKLM), `HKEY_CURRENT_USER` (HKCU), and `HKEY_CLASSES_ROOT` (HKCR) for information about the registered classes of objects, including their ProgIDs, CLSIDs, and other attributes.

Functions like `DllGetClassObject`, `DllUnregisterServer`, `DllRegisterServer`, `DllCanUnloadNow` will be exported and used by the application. it's a mandatory to have at least one exported function for COM Objects.

- `DllGetClassObject`: creates instances of the objects in the DLL.
- `DllRegisterServer` & `DllUnregisterServer`: registering and unregistering the COM components implemented by the DLL
- `DllCanUnloadNow`: is optional but it's used to determines whether it's safe to unload the DLL from memory.


## Explorer Context Menu Hijacking

### `IContextMenu` & `IShellExtInit` interfaces

`IShellExtInit` and `IContextMenu` are interfaces in the Windows API that allow developers to extend the Windows shell and add custom functionality to the context menu that appears when users right-click on a file or folder in Windows Explorer or Desktop.

To use the `IContextMenu` interface to perform actions when the user right-clicks on a file or folder in File Explorer, we need to implement the `IContextMenu::QueryContextMenu` and `IContextMenu::InvokeCommand` methods in the shell extension but we don't want to add any extensions so these 2 methods will just return true.


the `IShellExtInit::Initialize` method to receive information about the items that the user has selected. This method is called once for each right clicks and subsequently, the `CreateThread` function is called to create a new thread and execute our beacon.

![image](https://user-images.githubusercontent.com/75935486/219230859-88beeff1-42d7-418a-a0e6-48ab388ec0e9.png)

<br>

Now, let's talk a bit of `IUnknown` interface which is one of the most important interface for COM. It's composed of `QueryInterface` method which is used to query an object for the set of interfaces it supports.

![image](https://user-images.githubusercontent.com/75935486/219230767-dd2be089-e596-447e-906d-91088bc85d91.png)

In this code, we are populating a `QITAB` table with the interfaces supported by the object. The `QISearch` function is then used to determine if the object supports the requested interface, and will return the interface pointer if it does.

> If you wanna learn more about this here a [good blog](https://www.timdbg.com/posts/vtables/) of [@timmisiak](https://twitter.com/timmisiak)

### Shell Extension `ContextMenuHandlers`

The last important part of this is to register the context menu handler, all the magic is in `DllRegisterServer`. The `RegisterInprocServer` function is called to register the in-process COM server. This function takes 4 args including the CLSID of the object being registered and the threading model.
```c
    hr = RegisterInprocServer( szModule, CLSID_FileContextMenuExt, L"ContextMenuHijack.FileContextMenuExt Class", L"Apartment" );
    if ( SUCCEEDED( hr ) ) {
        hr = RegisterShellExtContextMenuHandler( L"AllFilesystemObjects", CLSID_FileContextMenuExt, L"ContextMenuHijack.FileContextMenuExt" );
    }
```
After registering the in-process COM server, `RegisterShellExtContextMenuHandler` is called to register the context menu handler in HKCR registry hive for all file system objects. The full path looks like that : `HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{B7CDF620-DB73-44C0-8611-832B261A0107}`



### Put it all together

once you have administrator privileges, you just have to register the DLL file in the registry with `regsvr32` : 

```powershell
regsvr32 "C:\path\to\ContextMenuHijack.dll"
```

And now you just have to wait that your target wants to interact with a file or folder by right-clicking on it and then you will have your beacon. This technique is still a bit risky because we don't really know when it happens, it is purely based on human behavior. But whatever it was cool to reproduce.


![persistence](https://user-images.githubusercontent.com/75935486/222849525-1f71c46d-59f4-4d8f-ad06-58d8158d73bc.gif)


## Conclusion

- this technique can be easily detected from the thread stack of `explorer.exe` or just simply from the registry with `Cm` kernel callbacks for example, it is up to you to use your own evasion tradecraft :)
![image](https://user-images.githubusercontent.com/75935486/212399032-3249579d-fff5-42e7-b18b-b3e7d13efaad.png)


## Credits 

- [https://github.com/rikka0w0/ExplorerContextMenuTweaker](https://github.com/rikka0w0/ExplorerContextMenuTweaker)
- [https://learn.microsoft.com/en-us/windows/win32/shell/how-to-implement-the-icontextmenu-interface?redirectedfrom=MSDN](https://learn.microsoft.com/en-us/windows/win32/shell/how-to-implement-the-icontextmenu-interface?redirectedfrom=MSDN)
- [https://www.codeproject.com/Articles/441/The-Complete-Idiot-s-Guide-to-Writing-Shell-Extens](https://www.codeproject.com/Articles/441/The-Complete-Idiot-s-Guide-to-Writing-Shell-Extens)
