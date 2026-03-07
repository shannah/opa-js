# RFC-0001: Open Prompt Archive (OPA)

**Status:** Draft  
**Version:** 0.1.0  
**Date:** 2026-03-04  
**Authors:** TBD  

---

## Abstract

This document specifies the **Open Prompt Archive (OPA)**, a portable, self-contained archive format for packaging AI agent prompts together with their session history, data assets, and execution metadata. OPA archives are distributable units that clients can extract and execute using any compatible AI agent in a sandboxed container environment. The format is based on the ZIP container (as used by JAR), ensuring broad toolchain compatibility.

---

## 1. Motivation

Modern AI-assisted workflows increasingly involve:

- **Reproducible prompt execution** — the ability to run a prompt against identical context and data, yielding consistent results.
- **Shareable agent tasks** — distributing a well-defined task (prompt + data) to another party or machine.
- **Session continuity** — preserving conversation history so agents can resume or audit a prior session.
- **Agent-agnostic portability** — decoupling the task definition from any specific AI provider or runtime.

No existing standard addresses all of these concerns in a single, self-describing, portable unit. OPA fills this gap by defining a minimal, open archive format that any client can execute by extracting its contents and invoking a conformant AI agent.

---

## 2. Design Goals

1. **Agent-agnostic.** The format must not assume a specific AI provider, model, or API. Clients choose their own agent.
2. **Container-friendly.** Archives must be straightforwardly extractable into a container filesystem for sandboxed execution.
3. **Human-readable metadata.** Manifest and prompt files must be plain text or common structured formats (JSON, YAML, Markdown).
4. **Toolchain compatible.** The archive format must be openable by standard ZIP tools (including `jar`, `unzip`, `7-Zip`).
5. **Extensible.** New capability fields can be added without breaking older clients.
6. **Minimal.** A valid OPA archive requires only a manifest and a prompt file.

---

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|------|------------|
| **Archive** | A single OPA file (`.opa`). |
| **Client** | Software that reads and executes an OPA archive. |
| **Agent** | The AI model or service invoked by the client to process the prompt. |
| **Session** | A recorded sequence of prior agent interactions included in the archive. |
| **Prompt** | The primary instruction or task specification for the agent. |
| **Data asset** | Any file included in the archive that the prompt may reference. |
| **Container** | An isolated execution environment (e.g., Docker, Podman, OCI sandbox) into which the archive is extracted. |

---

## 4. File Format

### 4.1 Container

An OPA archive is a **ZIP file** with the extension `.opa`. Implementations SHOULD also accept `.opa.jar` for interoperability with JAR-based toolchains. The ZIP central directory MUST be present and valid. ZIP64 extensions are permitted for archives exceeding 4 GB.

Archives SHOULD use `DEFLATE` compression for text-based entries and MAY use `STORE` for binary data assets where compression yields negligible benefit.

### 4.2 Directory Structure

```
<archive>.opa
│
├── META-INF/
│   └── MANIFEST.MF          # Required. Archive manifest.
│
├── prompt.md                # Required. The primary prompt file.
│
├── session/                 # Optional. Session history directory.
│   ├── history.json         # Required if session/ present.
│   └── attachments/         # Optional. Files referenced in session messages.
│       └── <any files>
│
└── data/                    # Optional. Data assets for the prompt.
    └── <arbitrary files and subdirectories>
```

Clients MUST treat any path outside of `META-INF/`, `session/`, and `data/` (other than `prompt.md`) as a data asset if encountered, for forward compatibility.

### 4.3 Path Safety

All entry paths within the archive MUST use forward-slash (`/`) separators. Clients MUST reject archives containing paths with `..` components or absolute paths (paths beginning with `/`). This prevents path traversal attacks during extraction.

---

## 5. Manifest (`META-INF/MANIFEST.MF`)

The manifest follows the [JAR manifest format](https://docs.oracle.com/en/java/docs/specs/jar/jar.html#jar-manifest): a sequence of `Name: Value` pairs separated by newlines, with sections separated by blank lines. Lines MUST NOT exceed 72 bytes; long values are continued by beginning the next line with a single space.

### 5.1 Required Fields

| Field | Description |
|-------|-------------|
| `Manifest-Version` | MUST be `1.0`. |
| `OPA-Version` | The OPA specification version. MUST be `0.1` for this revision. |
| `Prompt-File` | Archive-relative path to the primary prompt file. Defaults to `prompt.md`. |

### 5.2 Optional Fields

| Field | Description |
|-------|-------------|
| `Created-By` | Free-form string identifying the tool that created the archive. |
| `Created-At` | ISO 8601 UTC timestamp of archive creation (e.g., `2026-03-04T12:00:00Z`). |
| `Title` | Short human-readable title for the task. |
| `Description` | One-line summary of the archive's purpose. |
| `Agent-Hint` | RECOMMENDED model family or capability hint (e.g., `claude-3`, `gpt-4o`). Non-normative. Clients MAY ignore. |
| `Session-File` | Archive-relative path to the session history file. Defaults to `session/history.json` if `session/` exists. |
| `Data-Root` | Archive-relative path to the data asset root directory. Defaults to `data/`. |
| `Execution-Mode` | One of `interactive`, `batch`, or `autonomous`. Default: `interactive`. See §8. |
| `Schema-Extensions` | Space-separated list of extension URIs declared by this archive. See §9. |

### 5.3 Example Manifest

```
Manifest-Version: 1.0
OPA-Version: 0.1
Title: Summarise Q1 Sales Reports
Description: Summarise the attached regional CSV files and draft an execut
 ive brief.
Created-By: opa-cli 1.0.0
Created-At: 2026-03-04T09:15:00Z
Agent-Hint: claude-sonnet
Execution-Mode: batch
Prompt-File: prompt.md
Session-File: session/history.json
Data-Root: data/
```

---

## 6. Prompt File

### 6.1 Format

The prompt file is a **UTF-8 encoded Markdown** document. Clients MUST pass the full content of this file to the agent as the initial user message (or system prompt, per client policy — see §7).

### 6.2 Data Asset References

The prompt MAY reference data assets using paths relative to the archive root, enclosed in backticks or written as bare relative paths. Clients SHOULD resolve these references against the extracted archive directory and make the referenced files available to the agent (e.g., by including their content inline, providing file paths, or mounting them into the container).

**Example reference syntax (non-normative):**

```markdown
Please analyse the sales data in `data/q1/north-region.csv` and compare
it against `data/q1/south-region.csv`.
```

### 6.3 Template Variables

Prompt files MAY include template variables using the syntax `{{variable_name}}`. Clients MAY substitute these at runtime. The following variable names are RESERVED:

| Variable | Substituted With |
|----------|-----------------|
| `{{archive_name}}` | The base filename of the archive (without extension). |
| `{{extracted_path}}` | Absolute path to the extracted archive root in the container. |
| `{{timestamp}}` | ISO 8601 UTC execution time. |
| `{{agent}}` | The agent identifier selected by the client. |

---

## 7. Session History (`session/history.json`)

### 7.1 Purpose

The session history records prior interactions between a user and an agent. Clients MUST include session history in the agent context, prepended before the prompt, when executing an archive that contains a `session/history.json`.

### 7.2 Schema

`history.json` is a UTF-8 encoded JSON document conforming to the following structure:

```json
{
  "opa_version": "0.1",
  "session_id": "<UUID v4>",
  "created_at": "<ISO 8601 UTC>",
  "updated_at": "<ISO 8601 UTC>",
  "messages": [
    {
      "id": "<UUID v4 or sequential integer string>",
      "role": "user | assistant | system | tool",
      "content": "<string or content block array>",
      "timestamp": "<ISO 8601 UTC>",
      "metadata": {}
    }
  ]
}
```

#### 7.2.1 Message Roles

| Role | Description |
|------|-------------|
| `user` | Message originating from the human operator. |
| `assistant` | Message originating from the AI agent. |
| `system` | System-level instruction. Clients MAY inject before user messages. |
| `tool` | Result of a tool call. Clients that do not support tool use MAY omit these messages or convert them to `user` messages. |

#### 7.2.2 Content Blocks

The `content` field MAY be a plain string or an array of content block objects, enabling multi-modal history. Content block types:

```json
{ "type": "text", "text": "..." }
{ "type": "image", "source": { "type": "attachment", "path": "session/attachments/image.png" } }
{ "type": "file",  "source": { "type": "attachment", "path": "session/attachments/report.pdf" } }
{ "type": "tool_use",    "id": "...", "name": "...", "input": {} }
{ "type": "tool_result", "tool_use_id": "...", "content": "..." }
```

Attachment paths are archive-relative. Clients MUST extract referenced attachments before passing them to the agent.

#### 7.2.3 Example

```json
{
  "opa_version": "0.1",
  "session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "created_at": "2026-03-01T10:00:00Z",
  "updated_at": "2026-03-03T17:45:00Z",
  "messages": [
    {
      "id": "1",
      "role": "user",
      "content": "Can you start by reviewing the north region data?",
      "timestamp": "2026-03-01T10:00:00Z"
    },
    {
      "id": "2",
      "role": "assistant",
      "content": "Sure! I can see the north region CSV has three sheets...",
      "timestamp": "2026-03-01T10:00:05Z"
    }
  ]
}
```

---

## 8. Data Assets (`data/`)

### 8.1 Contents

The `data/` directory MAY contain any files and subdirectories. There are no restrictions on file type, name, or depth. Clients MUST extract the `data/` tree to the container filesystem and SHOULD make it available to the agent under a predictable path (e.g., `$OPA_DATA_ROOT`).

### 8.2 Data Index (Optional)

An archive MAY include a `data/INDEX.json` file enumerating the data assets with optional descriptions:

```json
{
  "assets": [
    {
      "path": "data/q1/north-region.csv",
      "description": "Q1 sales figures, North Region",
      "content_type": "text/csv"
    }
  ]
}
```

Clients MAY surface this index to agents as additional context.

---

## 9. Execution Model

### 9.1 Client Responsibilities

A conformant client MUST:

1. Validate the archive (ZIP integrity, manifest presence, OPA-Version recognition).
2. Extract the archive into an isolated environment.
3. Resolve the prompt file and session history per the manifest.
4. Construct the agent context: system messages (if any) → session history messages → prompt.
5. Invoke the agent with the constructed context.
6. Provide the `data/` directory to the agent via the container filesystem or equivalent mechanism.

### 9.2 Execution Modes

| Mode | Behaviour |
|------|-----------|
| `interactive` | Client presents agent responses to the user in real time; user may send follow-up messages. Session history SHOULD be updated by the client. |
| `batch` | Client runs the prompt to completion without user interaction. Output is captured and SHOULD be written to `output/` within the container. |
| `autonomous` | Agent may invoke tools and loop until a terminal condition is met. Client MUST enforce a configurable turn or token limit. |

### 9.3 Output Convention

Clients operating in `batch` or `autonomous` mode SHOULD write agent output to an `output/` directory inside the container at `$OPA_OUTPUT_ROOT`. Clients MAY package the output directory back into a new OPA archive with an updated session history for chaining.

### 9.4 Environment Variables

Clients MUST set the following environment variables in the container:

| Variable | Value |
|----------|-------|
| `OPA_VERSION` | The `OPA-Version` from the manifest. |
| `OPA_ARCHIVE_NAME` | The base filename of the archive (no extension). |
| `OPA_EXTRACTED_ROOT` | Absolute path to the extracted archive root. |
| `OPA_DATA_ROOT` | Absolute path to the extracted `data/` directory. |
| `OPA_OUTPUT_ROOT` | Absolute path to the designated output directory. |
| `OPA_EXECUTION_MODE` | The resolved execution mode. |

---

## 10. Extensions

Extensions allow third parties to introduce new fields and behaviours without conflicting with the core specification.

### 10.1 Extension Declaration

Extensions MUST be declared in the manifest's `Schema-Extensions` field as space-separated URIs:

```
Schema-Extensions: https://example.com/opa-ext/tool-config/v1
                   https://example.com/opa-ext/signing/v1
```

### 10.2 Extension Files

Extension data SHOULD be stored in `META-INF/extensions/<extension-id>/`. Clients that do not recognise an extension MUST NOT fail; they MUST skip unknown extension data.

### 10.3 Reserved Extension Namespace

The namespace `https://opa.dev/ext/` is reserved for officially ratified extensions. Third-party extensions MUST use their own domain.

---

## 11. Security Considerations

### 11.1 Path Traversal

Clients MUST validate all archive entry paths before extraction (see §4.3). Any path containing `..` or beginning with `/` MUST cause the client to reject the archive.

### 11.2 Prompt Injection

Session history and data assets are user-supplied content and MUST be treated as untrusted by the client. Clients SHOULD inform users when executing archives from unknown sources. Agents SHOULD be instructed not to follow instructions embedded in data assets that conflict with the primary prompt.

### 11.3 Resource Limits

Clients operating in `autonomous` mode MUST enforce maximum turn counts and token budgets to prevent runaway execution. Recommended defaults: 50 turns, 200,000 tokens.

### 11.4 Signing (Future Work)

A signing extension is planned to allow archive authors to sign manifests and contents. Until ratified, clients MAY implement signing using `META-INF/SIGNATURE.SF` following the JAR signing convention.

### 11.5 Sensitive Data

Archives MAY contain sensitive data. Authors SHOULD encrypt archives containing credentials, PII, or proprietary information. The core format does not mandate encryption; an encryption extension is anticipated.

---

## 12. MIME Type and File Extension

| Property | Value |
|----------|-------|
| File extension | `.opa` |
| MIME type | `application/vnd.opa+zip` |
| Alternative extension | `.opa.jar` (for JAR toolchain compatibility) |

---

## 13. Versioning

The `OPA-Version` field in the manifest identifies the specification version. Clients SHOULD warn and MAY refuse to execute archives with a higher major version than they support. Minor version increments are backwards-compatible additions.

This document defines version `0.1`. Version `1.0` will be published following at least two independent interoperable implementations.

---

## 14. Relation to Existing Formats

| Format | Relationship |
|--------|-------------|
| JAR | OPA uses the same ZIP-based container and manifest syntax. JAR tooling can inspect and extract OPA archives. |
| OCI Image | OPA is not an OCI image; it is extracted *into* an OCI container, not used *as* one. |
| LangChain serialization | OPA is agent-agnostic and does not encode framework-specific chain definitions. |
| OpenAI Assistant files | OPA is format-level; it does not encode provider-specific assistant configuration. |

---

## 15. Reference Implementation Notes

A minimal client implementation MUST:

- Accept a path to a `.opa` file.
- Extract the archive to a temporary directory with path-safety validation.
- Parse `META-INF/MANIFEST.MF`.
- Read `prompt.md` (or the value of `Prompt-File`).
- If `session/history.json` exists, parse and prepend it to the agent context.
- Invoke the configured agent with the full context.
- Set the required environment variables.

A reference CLI implementation (`opa-run`) and a Java library (`opa-core`) are planned as companion deliverables to this specification.

---

## 16. Example Archive Layout

```
sales-summary.opa
│
├── META-INF/
│   └── MANIFEST.MF
│
├── prompt.md
│
├── session/
│   ├── history.json
│   └── attachments/
│       └── previous-draft.md
│
└── data/
    ├── INDEX.json
    ├── q1/
    │   ├── north-region.csv
    │   └── south-region.csv
    └── reference/
        └── targets-2026.xlsx
```

---

## Appendix A: Manifest Field Summary

| Field | Required | Default |
|-------|----------|---------|
| `Manifest-Version` | Yes | — |
| `OPA-Version` | Yes | — |
| `Prompt-File` | No | `prompt.md` |
| `Session-File` | No | `session/history.json` |
| `Data-Root` | No | `data/` |
| `Execution-Mode` | No | `interactive` |
| `Title` | No | — |
| `Description` | No | — |
| `Agent-Hint` | No | — |
| `Created-By` | No | — |
| `Created-At` | No | — |
| `Schema-Extensions` | No | — |

---

## Appendix B: JSON Schema for `history.json`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://opa.dev/schema/history/0.1",
  "type": "object",
  "required": ["opa_version", "session_id", "messages"],
  "properties": {
    "opa_version": { "type": "string" },
    "session_id":   { "type": "string", "format": "uuid" },
    "created_at":   { "type": "string", "format": "date-time" },
    "updated_at":   { "type": "string", "format": "date-time" },
    "messages": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["role", "content"],
        "properties": {
          "id":        { "type": "string" },
          "role":      { "enum": ["user", "assistant", "system", "tool"] },
          "content":   {},
          "timestamp": { "type": "string", "format": "date-time" },
          "metadata":  { "type": "object" }
        }
      }
    }
  }
}
```

---

## Appendix C: Changelog

| Version | Date | Notes |
|---------|------|-------|
| 0.1.0 | 2026-03-04 | Initial draft. |

---

*End of RFC-0001*
