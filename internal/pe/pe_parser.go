package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
)

func Load(path string) (*pe.File, error) {
	return pe.Open(path)
}

func Parse(path string) (*PEInfo, error) {
	peFile, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open PE: %w", err)
	}
	defer peFile.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	result := &PEInfo{}

	result.DOSHeader, err = parseDOSHeader(raw)
	if err != nil {
		return nil, err
	}

	result.PESignature, err = parsePESignature(raw, result.DOSHeader.ELfanew)
	if err != nil {
		return nil, err
	}

	result.COFFHeader = parseCOFFHeader(peFile)
	result.OptionalHeader = parseOptionalHeader(peFile)
	result.Sections = parseSections(peFile)
	result.Imports = parseImports(peFile)
	result.Exports = parseExports(peFile, raw)
	result.Resources = parseResources(peFile, raw)
	result.TLSCallbacks = parseTLSCallbacks(peFile, raw)

	return result, nil
}

// ---------------------------------------------------------------------------
// DOS Header
// ---------------------------------------------------------------------------

func parseDOSHeader(raw []byte) (DOSHeaderInfo, error) {
	if len(raw) < 64 {
		return DOSHeaderInfo{}, fmt.Errorf("file too small for DOS header")
	}
	magic := string(raw[0:2])
	if magic != "MZ" {
		return DOSHeaderInfo{}, fmt.Errorf("invalid DOS magic: %q", magic)
	}
	return DOSHeaderInfo{
		Magic:   magic,
		ELfanew: binary.LittleEndian.Uint32(raw[60:64]),
	}, nil
}

// ---------------------------------------------------------------------------
// PE Signature
// ---------------------------------------------------------------------------

func parsePESignature(raw []byte, offset uint32) (string, error) {
	end := offset + 4
	if uint32(len(raw)) < end {
		return "", fmt.Errorf("file too small for PE signature at offset 0x%X", offset)
	}
	sig := raw[offset:end]
	if sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0 {
		return "", fmt.Errorf("invalid PE signature: %X", sig)
	}
	return "PE\\0\\0", nil
}

// ---------------------------------------------------------------------------
// COFF / File Header
// ---------------------------------------------------------------------------

func parseCOFFHeader(f *pe.File) COFFHeaderInfo {
	h := f.FileHeader
	return COFFHeaderInfo{
		Machine:          machineToString(h.Machine),
		NumberOfSections: h.NumberOfSections,
		TimeDateStamp:    h.TimeDateStamp,
		Timestamp:        time.Unix(int64(h.TimeDateStamp), 0).UTC().Format(time.RFC3339),
		Characteristics:  fileCharsToString(h.Characteristics),
	}
}

// ---------------------------------------------------------------------------
// Optional Header
// ---------------------------------------------------------------------------

func parseOptionalHeader(f *pe.File) OptionalHeaderInfo {
	dirs := getDataDirectories(f)
	ddInfos := make([]DataDirectoryInfo, len(dirs))
	for i, d := range dirs {
		name := "Unknown"
		if i < len(dataDirectoryNames) {
			name = dataDirectoryNames[i]
		}
		ddInfos[i] = DataDirectoryInfo{
			Name:           name,
			VirtualAddress: d.VirtualAddress,
			Size:           d.Size,
		}
	}

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return OptionalHeaderInfo{
			Magic:               "PE32",
			AddressOfEntryPoint: oh.AddressOfEntryPoint,
			ImageBase:           uint64(oh.ImageBase),
			SectionAlignment:    oh.SectionAlignment,
			FileAlignment:       oh.FileAlignment,
			Subsystem:           subsystemToString(oh.Subsystem),
			DllCharacteristics:  dllCharsToString(oh.DllCharacteristics),
			SizeOfImage:         oh.SizeOfImage,
			SizeOfHeaders:       oh.SizeOfHeaders,
			DataDirectories:     ddInfos,
		}
	case *pe.OptionalHeader64:
		return OptionalHeaderInfo{
			Magic:               "PE32+",
			AddressOfEntryPoint: oh.AddressOfEntryPoint,
			ImageBase:           oh.ImageBase,
			SectionAlignment:    oh.SectionAlignment,
			FileAlignment:       oh.FileAlignment,
			Subsystem:           subsystemToString(oh.Subsystem),
			DllCharacteristics:  dllCharsToString(oh.DllCharacteristics),
			SizeOfImage:         oh.SizeOfImage,
			SizeOfHeaders:       oh.SizeOfHeaders,
			DataDirectories:     ddInfos,
		}
	default:
		return OptionalHeaderInfo{DataDirectories: ddInfos}
	}
}

// ---------------------------------------------------------------------------
// Section Table
// ---------------------------------------------------------------------------

func parseSections(f *pe.File) []SectionInfo {
	out := make([]SectionInfo, len(f.Sections))
	for i, s := range f.Sections {
		out[i] = SectionInfo{
			Name:             s.Name,
			VirtualSize:      s.VirtualSize,
			VirtualAddress:   s.VirtualAddress,
			SizeOfRawData:    s.Size,
			PointerToRawData: s.Offset,
			Characteristics:  sectionCharsToString(s.Characteristics),
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Import Table
// ---------------------------------------------------------------------------

func parseImports(f *pe.File) []ImportEntry {
	symbols, err := f.ImportedSymbols()
	if err != nil || len(symbols) == 0 {
		return nil
	}

	libMap := make(map[string][]string)
	var order []string

	for _, sym := range symbols {
		parts := strings.SplitN(sym, ":", 2)
		if len(parts) != 2 {
			continue
		}
		lib, fn := parts[0], parts[1]
		if _, exists := libMap[lib]; !exists {
			order = append(order, lib)
		}
		libMap[lib] = append(libMap[lib], fn)
	}

	imports := make([]ImportEntry, 0, len(order))
	for _, lib := range order {
		imports = append(imports, ImportEntry{
			Library:   lib,
			Functions: libMap[lib],
		})
	}
	return imports
}

// ---------------------------------------------------------------------------
// Export Table
// ---------------------------------------------------------------------------

func parseExports(f *pe.File, raw []byte) *ExportInfo {
	dirs := getDataDirectories(f)
	if len(dirs) < 1 || dirs[0].VirtualAddress == 0 {
		return nil
	}

	offset, ok := rvaToOffset(f.Sections, dirs[0].VirtualAddress)
	if !ok || int(offset)+40 > len(raw) {
		return nil
	}

	nameRVA := binary.LittleEndian.Uint32(raw[offset+12 : offset+16])
	base := binary.LittleEndian.Uint32(raw[offset+16 : offset+20])
	numFunctions := binary.LittleEndian.Uint32(raw[offset+20 : offset+24])
	numNames := binary.LittleEndian.Uint32(raw[offset+24 : offset+28])
	addrFunctions := binary.LittleEndian.Uint32(raw[offset+28 : offset+32])
	addrNames := binary.LittleEndian.Uint32(raw[offset+32 : offset+36])
	addrNameOrdinals := binary.LittleEndian.Uint32(raw[offset+36 : offset+40])

	dllName := ""
	if nOff, ok := rvaToOffset(f.Sections, nameRVA); ok {
		dllName = readCString(raw, nOff)
	}

	// Read function RVAs
	funcOff, ok := rvaToOffset(f.Sections, addrFunctions)
	if !ok {
		return nil
	}
	funcRVAs := make([]uint32, numFunctions)
	for i := uint32(0); i < numFunctions; i++ {
		off := funcOff + i*4
		if int(off)+4 > len(raw) {
			break
		}
		funcRVAs[i] = binary.LittleEndian.Uint32(raw[off : off+4])
	}

	// Map ordinal index -> name
	namesByOrdinal := make(map[uint16]string)
	namesOff, ok1 := rvaToOffset(f.Sections, addrNames)
	ordinalsOff, ok2 := rvaToOffset(f.Sections, addrNameOrdinals)
	if ok1 && ok2 {
		for i := uint32(0); i < numNames; i++ {
			nOff := namesOff + i*4
			oOff := ordinalsOff + i*2
			if int(nOff)+4 > len(raw) || int(oOff)+2 > len(raw) {
				break
			}
			nRVA := binary.LittleEndian.Uint32(raw[nOff : nOff+4])
			ordIdx := binary.LittleEndian.Uint16(raw[oOff : oOff+2])
			if strOff, ok := rvaToOffset(f.Sections, nRVA); ok {
				namesByOrdinal[ordIdx] = readCString(raw, strOff)
			}
		}
	}

	var funcs []ExportFunc
	for i := uint32(0); i < numFunctions; i++ {
		if funcRVAs[i] == 0 {
			continue
		}
		funcs = append(funcs, ExportFunc{
			Name:    namesByOrdinal[uint16(i)],
			Ordinal: base + i,
			RVA:     funcRVAs[i],
		})
	}

	if len(funcs) == 0 {
		return nil
	}
	return &ExportInfo{DLLName: dllName, Functions: funcs}
}

// ---------------------------------------------------------------------------
// Resource Table
// ---------------------------------------------------------------------------

func parseResources(f *pe.File, raw []byte) []ResourceEntry {
	dirs := getDataDirectories(f)
	if len(dirs) <= 2 || dirs[2].VirtualAddress == 0 {
		return nil
	}

	base, ok := rvaToOffset(f.Sections, dirs[2].VirtualAddress)
	if !ok {
		return nil
	}

	var entries []ResourceEntry
	walkResourceDir(raw, base, base, 0, 0, "", &entries)
	return entries
}

func walkResourceDir(raw []byte, base, offset uint32, depth int, typeID uint32, name string, out *[]ResourceEntry) {
	if depth > 3 || int(offset)+16 > len(raw) {
		return
	}

	numNamed := binary.LittleEndian.Uint16(raw[offset+12 : offset+14])
	numID := binary.LittleEndian.Uint16(raw[offset+14 : offset+16])
	total := int(numNamed) + int(numID)

	for i := 0; i < total; i++ {
		entryOff := offset + 16 + uint32(i)*8
		if int(entryOff)+8 > len(raw) {
			break
		}

		nameOrID := binary.LittleEndian.Uint32(raw[entryOff : entryOff+4])
		dataOff := binary.LittleEndian.Uint32(raw[entryOff+4 : entryOff+8])

		curType := typeID
		curName := name

		switch depth {
		case 0:
			if nameOrID&0x80000000 != 0 {
				curType = nameOrID & 0x7FFFFFFF
			} else {
				curType = nameOrID
			}
		case 1:
			if nameOrID&0x80000000 != 0 {
				strOff := base + (nameOrID & 0x7FFFFFFF)
				curName = readResourceName(raw, strOff)
			} else {
				curName = fmt.Sprintf("#%d", nameOrID)
			}
		}

		if dataOff&0x80000000 != 0 {
			subDir := base + (dataOff & 0x7FFFFFFF)
			walkResourceDir(raw, base, subDir, depth+1, curType, curName, out)
		} else {
			deOff := base + dataOff
			if int(deOff)+16 > len(raw) {
				continue
			}
			dataRVA := binary.LittleEndian.Uint32(raw[deOff : deOff+4])
			size := binary.LittleEndian.Uint32(raw[deOff+4 : deOff+8])

			lang := uint16(0)
			if depth == 2 {
				lang = uint16(nameOrID & 0xFFFF)
			}

			*out = append(*out, ResourceEntry{
				Type:     resourceTypeToString(curType),
				ID:       curName,
				Language: lang,
				Size:     size,
				DataRVA:  dataRVA,
			})
		}
	}
}

func readResourceName(raw []byte, offset uint32) string {
	if int(offset)+2 > len(raw) {
		return ""
	}
	length := binary.LittleEndian.Uint16(raw[offset : offset+2])
	end := offset + 2 + uint32(length)*2
	if int(end) > len(raw) {
		return ""
	}
	chars := make([]byte, length)
	for i := uint16(0); i < length; i++ {
		chars[i] = raw[offset+2+uint32(i)*2]
	}
	return string(chars)
}

// ---------------------------------------------------------------------------
// TLS Callbacks
// ---------------------------------------------------------------------------

func parseTLSCallbacks(f *pe.File, raw []byte) []uint64 {
	dirs := getDataDirectories(f)
	if len(dirs) <= 9 || dirs[9].VirtualAddress == 0 {
		return nil
	}

	tlsOff, ok := rvaToOffset(f.Sections, dirs[9].VirtualAddress)
	if !ok {
		return nil
	}

	imageBase := getImageBase(f)
	wide := is64Bit(f)

	var callbacksVA uint64
	if wide {
		if int(tlsOff)+40 > len(raw) {
			return nil
		}
		callbacksVA = binary.LittleEndian.Uint64(raw[tlsOff+24 : tlsOff+32])
	} else {
		if int(tlsOff)+24 > len(raw) {
			return nil
		}
		callbacksVA = uint64(binary.LittleEndian.Uint32(raw[tlsOff+12 : tlsOff+16]))
	}

	if callbacksVA == 0 {
		return nil
	}

	cbRVA := uint32(callbacksVA - imageBase)
	cbOff, ok := rvaToOffset(f.Sections, cbRVA)
	if !ok {
		return nil
	}

	var callbacks []uint64
	for {
		var cb uint64
		if wide {
			if int(cbOff)+8 > len(raw) {
				break
			}
			cb = binary.LittleEndian.Uint64(raw[cbOff : cbOff+8])
			cbOff += 8
		} else {
			if int(cbOff)+4 > len(raw) {
				break
			}
			cb = uint64(binary.LittleEndian.Uint32(raw[cbOff : cbOff+4]))
			cbOff += 4
		}
		if cb == 0 {
			break
		}
		callbacks = append(callbacks, cb)
	}
	return callbacks
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func getDataDirectories(f *pe.File) []pe.DataDirectory {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return oh.DataDirectory[0:oh.NumberOfRvaAndSizes]
	case *pe.OptionalHeader64:
		return oh.DataDirectory[0:oh.NumberOfRvaAndSizes]
	default:
		return nil
	}
}

func getImageBase(f *pe.File) uint64 {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	default:
		return 0
	}
}

func is64Bit(f *pe.File) bool {
	_, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	return ok
}

func rvaToOffset(sections []*pe.Section, rva uint32) (uint32, bool) {
	for _, s := range sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return rva - s.VirtualAddress + s.Offset, true
		}
	}
	return 0, false
}

func readCString(data []byte, offset uint32) string {
	if int(offset) >= len(data) {
		return ""
	}
	end := offset
	for int(end) < len(data) && data[end] != 0 {
		end++
	}
	return string(data[offset:end])
}
