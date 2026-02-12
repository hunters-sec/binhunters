# Binhunters

> Ghidra on steroids — but for hunters.

Binhunters is a custom-built reverse engineering framework forked from [NSA Ghidra](https://github.com/NationalSecurityAgency/ghidra). It supercharges the binary analysis workflow with better decompiler output, instant triage capabilities, enhanced graph visualizations, integrated documentation, and a fully rebranded experience designed for serious reverse engineers and malware analysts.

![Binhunters](binhunterswithlogo.jpg)

---

## What's Different

Binhunters isn't a plugin or extension — it's a **source-level fork** of Ghidra with modifications to the decompiler engine (C++), the graph renderers (Java/jungrapht/Jung), the UI framework, and the analysis pipeline.

### Improved Decompiler
- **Fewer unnecessary casts** — suppresses redundant `(int)` / `(uint)` / `(ulong)` casts when sizes match
- **Better variable names** — loop counters use `i`, `j`, `k` instead of `local_XX`
- **Cleaner output** — eliminates redundant zero/sign extension chains

### Triage Panel
- One-click binary overview visible as a docked tab
- Shows binary metadata, section map with permissions, function stats, interesting strings, and categorized imports
- Instantly tells you what a binary does before you read a single instruction

### Context Sidebar
- Dynamic panel that updates as you navigate
- Shows function signature, callers, callees, local variables, and referenced strings for the current cursor position
- No more switching between five different panels to get basic context

### Variable Tracker
- Identifies global variables shared across multiple functions
- **Global Variables** tab: all globals sorted by usage count with color-coded importance
- **Current Function** tab: parameters, locals, global data accessed, strings, and data connections
- **Shared Data** tab: variables used by 2+ functions — key dependencies between code sections
- Red = used by 10+ functions, Orange = 5-9, Blue = 2-4

### Export C Code
- **Entire Binary as Single File**: All decompiled functions in one `.c` file with type definitions, forward declarations, and organized implementations
- **By Namespace**: One `.c` file per class/namespace plus shared `types.h`
- **Current Function**: Quick export of just what you're looking at
- Includes binary metadata, language detection, and proper C headers

### Bulk Export
- `File > Export All Decompiled Code` exports every function's decompiled C to an organized directory tree
- Outputs organized by namespace, category, imports, strings, and types
- Feed directly into external analysis tools, grep, or LLMs

### Source Language Detection
- Automatically identifies the source language: C, C++, Objective-C, Swift, Rust, Go, Java/Kotlin, C#/.NET
- Analyzes symbol patterns, section names, and import libraries
- Shows confidence level (high/medium/low) in the Triage Panel
- Used in exports for proper file headers

### Enhanced Graphs
- **Function Graph**: Working edge strokes (dashed=conditional, thick=unconditional, thin=fallthrough) + **T/F branch labels**
- **Block Flow / Code Flow**: Edge labels showing `Cond`, `Fall`, `Jump`, `Call` on every connection
- **Call Graph**: Function name + address in labels, rich tooltips with full signature, **xN** edge labels for multi-call sites
- **Max graph nodes** increased from 500 to 2000 for large function support

### Interactive Console
- Enhanced Python REPL welcome banner with available variables and quick examples
- Pre-loaded: `currentProgram`, `currentAddress`, `currentSelection`, `monitor`
- Full Ghidra API access for scripting on the fly

### Integrated Documentation
- `Documentation` menu with searchable, categorized guides
- Covers: Program Tree, Symbols, Data Types, Functions, Decompiler, Graphs, Scripting, Analysis, Navigation
- 45+ topics with 35 practical tips
- Tree sidebar + HTML content viewer with search filtering

### Tip of the Day — Disabled
- Tips moved into the Documentation panel
- No more popups on startup slowing down your workflow

---

## Building from Source

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **JDK** | 21+ | OpenJDK or Oracle JDK |
| **Gradle** | 8.5+ | Included wrapper (`./gradlew`) — no manual install needed |
| **Python** | 3.9 - 3.14 | For PyGhidra/Jython support |
| **Git** | 2.x+ | For cloning |

### Clone

```bash
git clone https://github.com/hunters-sec/binhunters.git
cd binhunters
```

---

### Build on macOS

```bash
# Install JDK 21 (if not installed)
brew install openjdk@21
export JAVA_HOME=$(/usr/libexec/java_home -v 21)

# Build
./gradlew buildGhidra

# Extract
unzip build/dist/ghidra_*_mac_*.zip -d ~/Desktop/Binhunters
cd ~/Desktop/Binhunters/ghidra_*

# Remove quarantine flag (macOS blocks unsigned apps)
xattr -r -d com.apple.quarantine .

# Run
./ghidraRun
```

**Apple Silicon (M1/M2/M3/M4):** Builds natively for `mac_arm_64`. No Rosetta needed.

**Intel Mac:** Builds for `mac_x86_64` automatically.

---

### Build on Linux

```bash
# Install JDK 21 (Ubuntu/Debian)
sudo apt update
sudo apt install openjdk-21-jdk

# Or on Fedora/RHEL
sudo dnf install java-21-openjdk-devel

# Or on Arch
sudo pacman -S jdk21-openjdk

# Verify Java
java -version   # Should show 21.x

# Build
./gradlew buildGhidra

# Extract
unzip build/dist/ghidra_*_linux_*.zip -d ~/Binhunters
cd ~/Binhunters/ghidra_*

# Run
./ghidraRun
```

**Headless mode (servers/CI):**
```bash
# Run analysis without GUI
./support/analyzeHeadless /path/to/project ProjectName \
    -import /path/to/binary \
    -postScript MyScript.java
```

---

### Build on Windows

```powershell
# Install JDK 21
# Download from: https://adoptium.net/temurin/releases/?version=21
# Or use winget:
winget install EclipseAdoptium.Temurin.21.JDK

# Set JAVA_HOME (adjust path to your JDK install)
set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-21

# Build
gradlew.bat buildGhidra

# Extract the zip from build\dist\
# Extract to: C:\Binhunters\

# Run
ghidraRun.bat
```

**Windows Defender Note:** Windows may flag the build. Add the Binhunters directory to Windows Defender exclusions if needed.

---

### Build Options

```bash
# Build only (no zip)
./gradlew assemble

# Run tests
./gradlew test

# Build specific module
./gradlew :Base:compileJava

# Clean build
./gradlew clean buildGhidra

# Build with parallel execution (faster)
./gradlew buildGhidra --parallel

# Show all available tasks
./gradlew tasks
```

---

## Architecture

Binhunters modifies Ghidra at the source level across multiple layers:

| Layer | What Changed | Why |
|-------|-------------|-----|
| **Decompiler Engine** (C++) | New simplification rules in `ruleaction.cc` | Cleaner pseudocode output |
| **Graph Framework** (Java) | `VisualEdgeRenderer`, `GraphDisplayOptions`, `DefaultGraphRenderer` | Edge labels, stroke hooks, node limits |
| **Function Graph** (Jung) | `FGEdgeRenderer`, `FunctionGraphFactory` | Working strokes, T/F labels |
| **Block/Code Flow** (jungrapht) | `ProgramGraphDisplayOptions`, `BlockGraphTask` | Edge label rendering, flow labels |
| **Call Graph** (Jung) | `FcgComponent`, `FcgEdge`, `FcgProvider`, `FcgTooltipProvider` | Call counts, rich tooltips |
| **Plugins** (Java) | Triage, Context Sidebar, Documentation, Bulk Export, Variable Tracker, Export C Code | New analysis features |
| **Branding** | Icons, splash, app name, titles | Binhunters identity |

---

## Modified Files

See [CHANGELOG.md](CHANGELOG.md) for the complete list of every file modified with detailed descriptions.

### Quick Count
- **~35 files modified** across the Ghidra source
- **~13 new files created** (plugins, providers, content)
- **C++ decompiler rules** in `ruleaction.cc` / `ruleaction.hh`
- **Java plugins** in `Features/Base/`, `Features/Decompiler/`, `Features/FunctionGraph/`, `Features/GraphFunctionCalls/`, `Features/GraphServices/`, `Features/ProgramGraph/`
- **Icons** in `Framework/Gui/`, `Features/Base/`, `RuntimeScripts/`

---

## Usage

### Quick Start
1. Import a binary: `File > Import File`
2. Click **Analyze** when prompted
3. Check the **Triage Panel** tab for instant overview
4. Navigate functions in the Listing, view decompiled code on the right
5. Press `G` to go to address, `L` to rename, `;` to comment
6. Open `Documentation` menu for full feature guides

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `G` | Go to address/label |
| `L` | Rename symbol |
| `T` | Change data type |
| `;` | Add comment |
| `F` | Create function |
| `D` | Define data |
| `C` | Disassemble |
| `Space` | Toggle Function Graph |
| `Ctrl+Shift+F` | Search all memory |
| `Alt+Left/Right` | Navigate history |
| `Ctrl+D` | Add bookmark |
| `F1` | Help for current panel |

### Scripting

Open `Window > Python` for the interactive console:

```python
# Get current function
func = getFunctionAt(currentAddress)
print(func.getSignature())

# Count all functions
fm = currentProgram.getFunctionManager()
print('Functions: %d' % fm.getFunctionCount())

# Find cross-references
refs = getReferencesTo(currentAddress)
for ref in refs:
    print(ref.getFromAddress())

# List all imports
for sym in currentProgram.getSymbolTable().getExternalSymbols():
    print(sym.getName())
```

---

## License

Binhunters is based on Ghidra, which is licensed under the [Apache License 2.0](LICENSE).

All Binhunters modifications are also released under Apache 2.0.

---

## Credits

- **[NSA](https://www.nsa.gov)** — Original Ghidra framework
- **[Binhunters](https://github.com/hunters-sec)** — Custom modifications, triage panel, documentation system, graph enhancements, decompiler improvements, rebranding

---

*Reverse Engineering & Malware Analysis*
