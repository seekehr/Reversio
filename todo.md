STAGE 1 — Build The Core Data Pipeline

NEXT STEP #2
Build Function Chunking

THIS is one of the most important concepts.

DO NOT DO THIS
Entire executable → AI

Terrible architecture.

DO THIS
1 function = 1 semantic chunk

Example chunk:

{
  "name": "FUN_140001220",
  "imports": [
    "OpenProcess",
    "WriteProcessMemory",
    "CreateRemoteThread"
  ],
  "pseudocode": "..."
}

Each function becomes:

searchable
embeddable
retrievable