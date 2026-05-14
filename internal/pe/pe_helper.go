package pe

import (
	"fmt"
	"strings"
)

// machineTypes maps COFF machine type constants to human-readable architecture names.
// Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
var machineTypes = map[uint16]string{
	0x0:    "UNKNOWN",
	0x14c:  "I386",
	0x166:  "R4000",
	0x169:  "WCEMIPSV2",
	0x1a2:  "SH3",
	0x1a3:  "SH3DSP",
	0x1a6:  "SH4",
	0x1a8:  "SH5",
	0x1c0:  "ARM",
	0x1c2:  "THUMB",
	0x1c4:  "ARMNT",
	0x1d3:  "AM33",
	0x200:  "IA64",
	0x266:  "MIPS16",
	0x366:  "MIPSFPU",
	0x466:  "MIPSFPU16",
	0x5064: "RISCV64",
	0x8664: "AMD64",
	0xaa64: "ARM64",
}

// fileCharacteristics defines COFF header characteristic bit flags that describe
// attributes of the PE file (executable, DLL, large-address-aware, etc.).
var fileCharacteristics = []struct {
	Flag uint16
	Name string
}{
	{0x0001, "RELOCS_STRIPPED"},
	{0x0002, "EXECUTABLE_IMAGE"},
	{0x0004, "LINE_NUMS_STRIPPED"},
	{0x0008, "LOCAL_SYMS_STRIPPED"},
	{0x0010, "AGGRESSIVE_WS_TRIM"},
	{0x0020, "LARGE_ADDRESS_AWARE"},
	{0x0080, "BYTES_REVERSED_LO"},
	{0x0100, "32BIT_MACHINE"},
	{0x0200, "DEBUG_STRIPPED"},
	{0x0400, "REMOVABLE_RUN_FROM_SWAP"},
	{0x0800, "NET_RUN_FROM_SWAP"},
	{0x1000, "SYSTEM"},
	{0x2000, "DLL"},
	{0x4000, "UP_SYSTEM_ONLY"},
	{0x8000, "BYTES_REVERSED_HI"},
}

// subsystems maps the PE optional header Subsystem field to a readable name,
// indicating the environment required to run the image (GUI, console, EFI, etc.).
var subsystems = map[uint16]string{
	0:  "UNKNOWN",
	1:  "NATIVE",
	2:  "WINDOWS_GUI",
	3:  "WINDOWS_CUI",
	5:  "OS2_CUI",
	7:  "POSIX_CUI",
	9:  "WINDOWS_CE_GUI",
	10: "EFI_APPLICATION",
	11: "EFI_BOOT_SERVICE_DRIVER",
	12: "EFI_RUNTIME_DRIVER",
	13: "EFI_ROM",
	14: "XBOX",
	16: "WINDOWS_BOOT_APPLICATION",
}

// dllCharacteristicFlags defines DLL characteristics bit flags for security
// features like ASLR (DYNAMIC_BASE), DEP (NX_COMPAT), and Control Flow Guard.
var dllCharacteristicFlags = []struct {
	Flag uint16
	Name string
}{
	{0x0020, "HIGH_ENTROPY_VA"},
	{0x0040, "DYNAMIC_BASE"},
	{0x0080, "FORCE_INTEGRITY"},
	{0x0100, "NX_COMPAT"},
	{0x0200, "NO_ISOLATION"},
	{0x0400, "NO_SEH"},
	{0x0800, "NO_BIND"},
	{0x1000, "APPCONTAINER"},
	{0x2000, "WDM_DRIVER"},
	{0x4000, "GUARD_CF"},
	{0x8000, "TERMINAL_SERVER_AWARE"},
}

// sectionCharacteristicFlags defines per-section permission and content type flags
// (executable, readable, writable, contains code/data, etc.).
var sectionCharacteristicFlags = []struct {
	Flag uint32
	Name string
}{
	{0x00000008, "NO_PAD"},
	{0x00000020, "CODE"},
	{0x00000040, "INITIALIZED_DATA"},
	{0x00000080, "UNINITIALIZED_DATA"},
	{0x00000100, "LNK_OTHER"},
	{0x00000200, "LNK_INFO"},
	{0x00000800, "LNK_REMOVE"},
	{0x00001000, "LNK_COMDAT"},
	{0x00004000, "NO_DEFER_SPEC_EXC"},
	{0x00008000, "GPREL"},
	{0x01000000, "LNK_NRELOC_OVFL"},
	{0x02000000, "MEM_DISCARDABLE"},
	{0x04000000, "MEM_NOT_CACHED"},
	{0x08000000, "MEM_NOT_PAGED"},
	{0x10000000, "MEM_SHARED"},
	{0x20000000, "MEM_EXECUTE"},
	{0x40000000, "MEM_READ"},
	{0x80000000, "MEM_WRITE"},
}

// resourceTypes maps PE resource type IDs to their well-known names.
var resourceTypes = map[uint32]string{
	1:  "RT_CURSOR",
	2:  "RT_BITMAP",
	3:  "RT_ICON",
	4:  "RT_MENU",
	5:  "RT_DIALOG",
	6:  "RT_STRING",
	7:  "RT_FONTDIR",
	8:  "RT_FONT",
	9:  "RT_ACCELERATOR",
	10: "RT_RCDATA",
	11: "RT_MESSAGETABLE",
	12: "RT_GROUP_CURSOR",
	14: "RT_GROUP_ICON",
	16: "RT_VERSION",
	17: "RT_DLGINCLUDE",
	19: "RT_PLUGPLAY",
	20: "RT_VXD",
	21: "RT_ANICURSOR",
	22: "RT_ANIICON",
	23: "RT_HTML",
	24: "RT_MANIFEST",
}

// dataDirectoryNames provides the canonical name for each of the 16 data directory
// entries in the PE optional header (indices 0-15).
var dataDirectoryNames = [16]string{
	"Export Table",
	"Import Table",
	"Resource Table",
	"Exception Table",
	"Certificate Table",
	"Base Relocation Table",
	"Debug",
	"Architecture",
	"Global Ptr",
	"TLS Table",
	"Load Config Table",
	"Bound Import",
	"IAT",
	"Delay Import Descriptor",
	"CLR Runtime Header",
	"Reserved",
}

// machineToString converts a COFF machine type constant to its string representation.
func machineToString(m uint16) string {
	if s, ok := machineTypes[m]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN(0x%X)", m)
}

// fileCharsToString decodes a COFF characteristics bitmask into a pipe-separated string of flag names.
func fileCharsToString(c uint16) string {
	var flags []string
	for _, f := range fileCharacteristics {
		if c&f.Flag != 0 {
			flags = append(flags, f.Name)
		}
	}
	if len(flags) == 0 {
		return fmt.Sprintf("0x%X", c)
	}
	return strings.Join(flags, " | ")
}

// subsystemToString converts a PE subsystem ID to its human-readable name.
func subsystemToString(s uint16) string {
	if name, ok := subsystems[s]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", s)
}

// dllCharsToString decodes a DLL characteristics bitmask into a pipe-separated string of flag names.
func dllCharsToString(c uint16) string {
	var flags []string
	for _, f := range dllCharacteristicFlags {
		if c&f.Flag != 0 {
			flags = append(flags, f.Name)
		}
	}
	if len(flags) == 0 {
		return fmt.Sprintf("0x%X", c)
	}
	return strings.Join(flags, " | ")
}

// sectionCharsToString decodes section characteristics into a pipe-separated string of flag names.
func sectionCharsToString(c uint32) string {
	var flags []string
	for _, f := range sectionCharacteristicFlags {
		if c&f.Flag != 0 {
			flags = append(flags, f.Name)
		}
	}
	if len(flags) == 0 {
		return fmt.Sprintf("0x%X", c)
	}
	return strings.Join(flags, " | ")
}

// resourceTypeToString converts a resource type ID to its well-known name (e.g. RT_ICON).
func resourceTypeToString(id uint32) string {
	if s, ok := resourceTypes[id]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN(%d)", id)
}
