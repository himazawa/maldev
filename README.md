# MalDev

This is a collection of malware development techniques in Golang.
The main (and only) target is Windows.

## Payload Injection

This is a simple injection, using `VirtualAlloxEx` and `CreateRemoteThread` to execute a payload from a target process.

Build:

`go build codeinjection/main.go` 

Usage:

`codeinjection.exe -target="msdev.exe"`

The shellcode is located in `codeinjection/data/shellcode.bin` and will be embedded at build time, feel free to change it or write your own.

## Dll Injection

Same as payload injection but instead of injecting the full payloads, it writes the path to a dll in the target process and then execute it using `LoadLibraryA`

Build:

`go build dllinjection/main.go`

Usage:

`dllInjection.exe -target="msdev.exe" -dll="C:\fullpath\to\inject.dll`



