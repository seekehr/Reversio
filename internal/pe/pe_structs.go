package pe

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

type DOSHeaderInfo struct {
	Magic   string `json:"magic"`
	ELfanew uint32 `json:"e_lfanew"`
}

type COFFHeaderInfo struct {
	Machine          string `json:"machine"`
	NumberOfSections uint16 `json:"number_of_sections"`
	TimeDateStamp    uint32 `json:"timestamp_raw"`
	Timestamp        string `json:"timestamp"`
	Characteristics  string `json:"characteristics"`
}

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

type DataDirectoryInfo struct {
	Name           string `json:"name"`
	VirtualAddress uint32 `json:"virtual_address"`
	Size           uint32 `json:"size"`
}

type SectionInfo struct {
	Name             string `json:"name"`
	VirtualSize      uint32 `json:"virtual_size"`
	VirtualAddress   uint32 `json:"virtual_address"`
	SizeOfRawData    uint32 `json:"size_of_raw_data"`
	PointerToRawData uint32 `json:"pointer_to_raw_data"`
	Characteristics  string `json:"characteristics"`
}

type ImportEntry struct {
	Library   string   `json:"library"`
	Functions []string `json:"functions"`
}

type ExportInfo struct {
	DLLName   string       `json:"dll_name,omitempty"`
	Functions []ExportFunc `json:"functions"`
}

type ExportFunc struct {
	Name    string `json:"name,omitempty"`
	Ordinal uint32 `json:"ordinal"`
	RVA     uint32 `json:"rva"`
}

type ResourceEntry struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Language uint16 `json:"language"`
	Size     uint32 `json:"size"`
	DataRVA  uint32 `json:"data_rva"`
}
