# MalDev

This is a collection of techniques related to malware development techniques targeting Windows.

## Payload Injecion

This is a simple injection, using VirtualAlloxEx and CreateRemoteThread to execute a payload from a target process.

Build:

`go build codeinjection/main.go` 

Usage:

`./codeinjection -t="msdev.exe"`

The shellcode is located in `codeinjection/data/shellcode.bin` and will be embedded at build time, feel free to change it or write your own.

