package utils

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
	CreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
	Process32First = kernel32.NewProc("Process32FirstW")
	// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
	Process32Next = kernel32.NewProc("Process32NextW")
	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	VirtualAllocEx = kernel32.NewProc("VirtualAllocEx")
	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
	VirtualProtectEx = kernel32.NewProc("VirtualProtectEx")
	// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
	WriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
	CreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	// https://learn.microsoft.com/en-us/windows/console/freeconsole
	FreeConsole = kernel32.NewProc("FreeConsole")
)

// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
type ProcessEntry struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriorityClass   int32
	Reserved        uint32
	ExeFile         [windows.MAX_PATH]uint16
}

func createPsListSnapshot(flags, processID uint32) (uintptr, error) {
	var ret uintptr
	ret, _, err := CreateToolhelp32Snapshot.Call(
		uintptr(flags),
		uintptr(processID),
	)
	if ret == 0 {
		return ret, err
	}
	return ret, nil
}

func findProcessByName(snapshot uintptr, name string) (*ProcessEntry, error) {
	var entry ProcessEntry
	entry.Size = uint32(unsafe.Sizeof(entry))
	proc, _, _ := Process32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if proc == 0 {
		return nil, fmt.Errorf("error retrieving process info")
	}
	for {
		proc, _, _ := Process32Next.Call(
			uintptr(snapshot),
			uintptr(unsafe.Pointer(&entry)),
		)
		if proc == 0 {
			return nil, fmt.Errorf("no active process named %s found", name)
		}
		if strings.EqualFold(syscall.UTF16ToString(entry.ExeFile[:]), name) {
			return &entry, nil
		}
	}
}

func FindPIDFromProcessName(name string) (uint32, error) {
	snapshot, err := createPsListSnapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	process, err := findProcessByName(snapshot, name)
	if err != nil {
		return 0, err
	}
	return process.ProcessID, nil
}
