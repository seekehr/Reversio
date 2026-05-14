// Package rag implements chunking logic for Retrieval-Augmented Generation (RAG).
// It transforms structured analysis data (PE metadata, decompiled functions) into
// text chunks suitable for embedding and semantic search by an LLM.
package rag

import (
	"fmt"
	"strings"

	"github.com/seekehr/reversio/internal/info"
	"github.com/seekehr/reversio/internal/pe"
	"github.com/seekehr/reversio/internal/re_functions"
)

// Chunk represents a single unit of information for RAG indexing.
// Each chunk has a unique ID, a type category for filtering, and
// a text content string optimized for embedding similarity search.
type Chunk struct {
	ID      string
	Type    string
	Content string
}

// Chunker takes all available analysis data and produces a flat slice of Chunks.
// It delegates to specialized chunkers for each data type (PE headers, functions, etc.).
func Chunker(i *info.Info) []Chunk {
	var chunks []Chunk

	if i.PE != nil {
		chunks = append(chunks, chunkPE(i.PE)...)
	}

	if i.Functions != nil {
		chunks = append(chunks, chunkFunctions(i.Functions)...)
	}

	return chunks
}

// chunkPE breaks PE metadata into individual chunks: one combined headers chunk,
// plus separate chunks for each data directory, section, import, export, resource,
// and TLS callback. This granularity allows the LLM to retrieve only the relevant
// PE details for a given query.
func chunkPE(p *pe.PEInfo) []Chunk {
	var chunks []Chunk

	chunks = append(chunks, Chunk{
		ID:   "pe:headers",
		Type: "pe_headers",
		Content: fmt.Sprintf(
			"DOS Magic: %s, PE Signature: %s\n"+
				"COFF: Machine=%s, Sections=%d, Timestamp=%s, Characteristics=%s\n"+
				"Optional: Magic=%s, EntryPoint=0x%X, ImageBase=0x%X, SectionAlignment=%d, "+
				"FileAlignment=%d, Subsystem=%s, DllCharacteristics=%s, SizeOfImage=%d, SizeOfHeaders=%d",
			p.DOSHeader.Magic, p.PESignature,
			p.COFFHeader.Machine, p.COFFHeader.NumberOfSections, p.COFFHeader.Timestamp, p.COFFHeader.Characteristics,
			p.OptionalHeader.Magic, p.OptionalHeader.AddressOfEntryPoint, p.OptionalHeader.ImageBase,
			p.OptionalHeader.SectionAlignment, p.OptionalHeader.FileAlignment,
			p.OptionalHeader.Subsystem, p.OptionalHeader.DllCharacteristics,
			p.OptionalHeader.SizeOfImage, p.OptionalHeader.SizeOfHeaders,
		),
	})

	for idx, dd := range p.OptionalHeader.DataDirectories {
		if dd.Size == 0 && dd.VirtualAddress == 0 {
			continue
		}
		chunks = append(chunks, Chunk{
			ID:   fmt.Sprintf("pe:data_directory:%d", idx),
			Type: "pe_data_directory",
			Content: fmt.Sprintf("Data Directory: %s, VirtualAddress=0x%X, Size=%d",
				dd.Name, dd.VirtualAddress, dd.Size),
		})
	}

	for idx, sec := range p.Sections {
		chunks = append(chunks, Chunk{
			ID:   fmt.Sprintf("pe:section:%d", idx),
			Type: "pe_section",
			Content: fmt.Sprintf("Section: %s, VirtualSize=%d, VirtualAddress=0x%X, "+
				"SizeOfRawData=%d, PointerToRawData=0x%X, Characteristics=%s",
				sec.Name, sec.VirtualSize, sec.VirtualAddress,
				sec.SizeOfRawData, sec.PointerToRawData, sec.Characteristics),
		})
	}

	for idx, imp := range p.Imports {
		chunks = append(chunks, Chunk{
			ID:   fmt.Sprintf("pe:import:%d", idx),
			Type: "pe_import",
			Content: fmt.Sprintf("Import: %s from [%s]",
				imp.Library, strings.Join(imp.Functions, ", ")),
		})
	}

	if p.Exports != nil {
		for idx, exp := range p.Exports.Functions {
			name := exp.Name
			if name == "" {
				name = fmt.Sprintf("ordinal_%d", exp.Ordinal)
			}
			chunks = append(chunks, Chunk{
				ID:   fmt.Sprintf("pe:export:%d", idx),
				Type: "pe_export",
				Content: fmt.Sprintf("Export: %s (DLL=%s, Ordinal=%d, RVA=0x%X)",
					name, p.Exports.DLLName, exp.Ordinal, exp.RVA),
			})
		}
	}

	for idx, res := range p.Resources {
		chunks = append(chunks, Chunk{
			ID:   fmt.Sprintf("pe:resource:%d", idx),
			Type: "pe_resource",
			Content: fmt.Sprintf("Resource: Type=%s, ID=%s, Language=%d, Size=%d, DataRVA=0x%X",
				res.Type, res.ID, res.Language, res.Size, res.DataRVA),
		})
	}

	for idx, cb := range p.TLSCallbacks {
		chunks = append(chunks, Chunk{
			ID:      fmt.Sprintf("pe:tls_callback:%d", idx),
			Type:    "pe_tls_callback",
			Content: fmt.Sprintf("TLS Callback: Address=0x%X", cb),
		})
	}

	return chunks
}

// chunkFunctions creates one chunk per decompiled function, combining the function's
// metadata (name, address, size) with its pseudocode, imports, calls, and strings
// into a single self-contained text block for embedding.
func chunkFunctions(prog *re_functions.Program) []Chunk {
	chunks := make([]Chunk, 0, len(prog.Functions))

	for idx, fn := range prog.Functions {
		var b strings.Builder
		fmt.Fprintf(&b, "Function: %s at %s (size=%d)\n", fn.Name, fn.Address, fn.Size)

		if fn.Pseudocode != "" {
			fmt.Fprintf(&b, "Pseudocode:\n%s\n", strings.TrimSpace(fn.Pseudocode))
		}
		if len(fn.Imports) > 0 {
			fmt.Fprintf(&b, "Imports: [%s]\n", strings.Join(fn.Imports, ", "))
		}
		if len(fn.Calls) > 0 {
			fmt.Fprintf(&b, "Calls: [%s]\n", strings.Join(fn.Calls, ", "))
		}
		if len(fn.Strings) > 0 {
			fmt.Fprintf(&b, "Strings: [%s]\n", strings.Join(fn.Strings, ", "))
		}

		chunks = append(chunks, Chunk{
			ID:      fmt.Sprintf("func:%d:%s", idx, fn.Name),
			Type:    "function",
			Content: b.String(),
		})
	}

	return chunks
}
