// Package pe provides types and functions for parsing Windows Portable Executable (PE) files.
// It extracts structural metadata including headers, sections, imports, exports, resources,
// and TLS callbacks into JSON-serializable types suitable for further analysis.
package pe

// PEInfo holds the complete parsed representation of a PE file.
type PEInfo struct {
	DOSHeader      DOSHeaderInfo      `json:"dos_header"`
	PESignature    string             `json:"pe_signature"`
	COFFHeader     COFFHeaderInfo     `json:"coff_header"`
	OptionalHeader OptionalHeaderInfo `json:"optional_header"`
	Sections       []SectionInfo      `json:"sections"`
	Imports        []ImportEntry      `json:"imports"`
	Exports        *ExportInfo        `json:"exports,omitempty"`
	Resources      []ResourceEntry    `json:"resources,omitempty"`
	TLSCallbacks   []uint64           `json:"tls_callbacks,omitempty"`
}

// DOSHeaderInfo represents the legacy DOS header at the start of every PE file.
// ELfanew is the file offset pointing to the PE signature ("PE\0\0").
type DOSHeaderInfo struct {
	Magic   string `json:"magic"`
	ELfanew uint32 `json:"e_lfanew"`
}

// COFFHeaderInfo represents the COFF (Common Object File Format) header,
// which describes the target machine architecture, number of sections,
// compilation timestamp, and file-level characteristics flags.
type COFFHeaderInfo struct {
	Machine          string `json:"machine"`
	NumberOfSections uint16 `json:"number_of_sections"`
	TimeDateStamp    uint32 `json:"timestamp_raw"`
	Timestamp        string `json:"timestamp"`
	Characteristics  string `json:"characteristics"`
}

// OptionalHeaderInfo contains PE optional header fields that describe memory layout,
// entry point, subsystem type, and the data directory table. Despite the name, this
// header is mandatory for executable images.
type OptionalHeaderInfo struct {
	Magic               string              `json:"magic"`
	AddressOfEntryPoint uint32              `json:"address_of_entry_point"`
	ImageBase           uint64              `json:"image_base"`
	SectionAlignment    uint32              `json:"section_alignment"`
	FileAlignment       uint32              `json:"file_alignment"`
	Subsystem           string              `json:"subsystem"`
	DllCharacteristics  string              `json:"dll_characteristics"`
	SizeOfImage         uint32              `json:"size_of_image"`
	SizeOfHeaders       uint32              `json:"size_of_headers"`
	DataDirectories     []DataDirectoryInfo `json:"data_directories"`
}

// DataDirectoryInfo represents one entry in the PE data directory table,
// pointing to structures like the import table, export table, resources, etc.
type DataDirectoryInfo struct {
	Name           string `json:"name"`
	VirtualAddress uint32 `json:"virtual_address"`
	Size           uint32 `json:"size"`
}

// SectionInfo describes a single PE section (e.g. .text, .data, .rdata).
// VirtualAddress is the RVA when loaded into memory; PointerToRawData is the file offset.
type SectionInfo struct {
	Name             string `json:"name"`
	VirtualSize      uint32 `json:"virtual_size"`
	VirtualAddress   uint32 `json:"virtual_address"`
	SizeOfRawData    uint32 `json:"size_of_raw_data"`
	PointerToRawData uint32 `json:"pointer_to_raw_data"`
	Characteristics  string `json:"characteristics"`
}

// ImportEntry represents a single DLL dependency and the functions imported from it.
type ImportEntry struct {
	Library   string   `json:"library"`
	Functions []string `json:"functions"`
}

// ExportInfo holds the export table of a DLL, including the DLL name and all exported functions.
type ExportInfo struct {
	DLLName   string       `json:"dll_name,omitempty"`
	Functions []ExportFunc `json:"functions"`
}

// ExportFunc represents a single exported function with its name (if named), ordinal, and RVA.
type ExportFunc struct {
	Name    string `json:"name,omitempty"`
	Ordinal uint32 `json:"ordinal"`
	RVA     uint32 `json:"rva"`
}

// ResourceEntry represents a single resource embedded in the PE (icons, manifests, version info, etc.).
type ResourceEntry struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Language uint16 `json:"language"`
	Size     uint32 `json:"size"`
	DataRVA  uint32 `json:"data_rva"`
}
