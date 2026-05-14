# Reversio

An AI-powered reverse engineering platform built with Go and Ghidra that transforms Windows executables into searchable semantic knowledge. The system automates PE analysis, decompilation, function extraction, call graph reconstruction, and pseudocode generation, then uses embeddings and vector search to enable AI-assisted code understanding, malware capability analysis, and natural-language querying of binaries; even under stripped or partially obfuscated conditions.

---

## Quick Start (Docker)

The fastest way to get everything running. Requires only Docker Desktop.

### Prerequisites

- [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/) with WSL 2 backend
- ~15 GB disk space (Ghidra + Ollama model + images)
- 8 GB+ RAM
- NVIDIA GPU + [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html) (optional, for faster embeddings)

### Steps

```powershell
# 1. Clone the repo
git clone https://github.com/seekehr/reversio.git
cd reversio

# 2. Run the setup script
.\setup.ps1
```

That's it. The script will:
- Build the Reversio container (Go app + Ghidra + JDK)
- Start Qdrant (vector database) on port 6333
- Start Ollama (embedding server) on port 11434
- Pull the `qwen3-embedding:4b` model automatically
- Detect and configure GPU if available (falls back to CPU)

### Usage

```powershell
# Attach to the interactive REPL
docker attach reversio

# Inside the REPL, analyze a binary
> r /app/samples/target.exe
```

Copy `.exe` files into the `samples/` folder — it's mounted into the container at `/app/samples/`.

### Management Commands

```powershell
# View all service logs
docker compose logs -f

# Stop everything
.\setup.ps1 -Down

# Rebuild after code changes
.\setup.ps1

# Force CPU-only (skip GPU detection)
.\setup.ps1 -GpuDisable

# Skip rebuild, use cached images
.\setup.ps1 -NoBuild
```

### Service URLs

| Service | URL |
|---------|-----|
| Qdrant Dashboard | http://localhost:6333/dashboard |
| Qdrant API | http://localhost:6333 |
| Ollama API | http://localhost:11434 |

---

## Manual Setup (Without Docker)

If you prefer running everything natively on Windows.

### Prerequisites

| Dependency | Version | Download |
|-----------|---------|----------|
| Go | 1.24+ | https://go.dev/dl/ |
| Ghidra | 11.x+ | https://ghidra-sre.org/ |
| JDK | 17+ | https://adoptium.net/ |
| Ollama | latest | https://ollama.com/download |
| Qdrant | latest | https://qdrant.tech/documentation/quick-start/ |

### Steps

**1. Clone and install Go dependencies**

```powershell
git clone https://github.com/seekehr/reversio.git
cd reversio
go mod download
```

**2. Install and configure Ghidra**

- Download and extract Ghidra to a directory (e.g. `C:\ghidra`)
- Create a Ghidra projects directory:

```powershell
mkdir C:\ghidra-projects
```

**3. Install and start Ollama**

```powershell
# After installing Ollama, pull the embedding model
ollama pull qwen3-embedding:4b
```

Ollama runs in the background on `http://localhost:11434` by default.

**4. Install and start Qdrant**

```powershell
# Option A: Docker (just Qdrant)
docker run -p 6333:6333 -p 6334:6334 -v qdrant_data:/qdrant/storage qdrant/qdrant

# Option B: Download binary from https://github.com/qdrant/qdrant/releases
```

**5. Create the `.env` file**

```powershell
Copy-Item .example.env .env
```

Edit `.env` with your local paths:

```env
HEADLESS_GHIDRA_PATH=C:\ghidra\support
GHIDRA_PROJECT_PATH=C:\ghidra-projects
GHIDRA_SCRIPTS_PATH=C:\Users\YourName\reversio\resources\ghidra_scripts
```

**6. Run**

```powershell
go run .
```

Then in the REPL:

```
> r C:\path\to\target.exe
```

---

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `HEADLESS_GHIDRA_PATH` | Directory containing `analyzeHeadless.bat` (or `analyzeHeadless` on Linux) | `C:\ghidra\support` |
| `GHIDRA_PROJECT_PATH` | Directory where Ghidra stores its project files | `C:\ghidra-projects` |
| `GHIDRA_SCRIPTS_PATH` | Directory containing `ExportFunctions.java` | `.\resources\ghidra_scripts` |
| `OLLAMA_HOST` | Ollama base URL (optional, defaults to `http://localhost:11434`) | `http://ollama:11434` |
