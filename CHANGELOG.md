# Binhunters Changelog

All notable changes to Binhunters (forked from NSA Ghidra 12.1) are documented here.

---

## Phase 1: C++ Decompiler Quality Improvements

### Problem
Ghidra's decompiler produced verbose, hard-to-read C pseudocode with unnecessary casts, poor variable names, and redundant operations.

### Changes

- **`Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.cc`**
  - Added `RuleIntUintSameSizeCast` — suppresses unnecessary `(int)` / `(uint)` casts when operand sizes match in arithmetic contexts
  - Added `RuleRedundantIntExtension` — eliminates redundant zero/sign extension casts (e.g., `(ulong)(uint)x` simplified to `x`)
  - Both rules registered in `ActionDatabase::universalAction()` for all architectures

- **`Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.hh`**
  - Declared both new rule classes extending `Rule`

---

## Phase 2: Bulk Decompiled Code Export

### Problem
No way to export all decompiled code at once for external analysis tools, grep, or code review.

### Changes

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/export/ExportAllDecompiledAction.java`** (NEW)
  - Menu action: `File > Export All Decompiled Code`
  - Decompiles every function in a background task
  - Writes output organized into directories:
    - `functions/` — all functions by name
    - `by_namespace/` — grouped by class/namespace
    - `by_category/` — categorized (user-defined, auto-generated, thunks, external)
    - `imports/` — import summary by library
    - `strings/` — all defined strings with addresses
    - `types/` — type definitions as C headers
    - `summary.txt` — binary overview and statistics

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/export/ExportAllDecompiledPlugin.java`** (NEW)
  - Plugin wrapper registered in CodeBrowser

---

## Phase 3: Triage Panel

### Problem
Opening a new binary requires clicking through multiple panels to understand what it contains. No quick-overview capability.

### Changes

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/triage/TriagePlugin.java`** (NEW)
  - Plugin providing the triage panel

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/triage/TriageProvider.java`** (NEW)
  - Dockable panel showing:
    - Binary metadata (format, architecture, endianness, entry point, compiler)
    - Section map with visual size bars and permissions (rwx)
    - Function statistics (total, named, auto-generated, average size)
    - Interesting strings (URLs, file paths, error messages, crypto strings)
    - Import categories (networking, file I/O, memory, process, crypto, registry)
  - Refreshes automatically when a new program is opened

---

## Phase 4: Context Sidebar

### Problem
Analysts need to constantly switch between panels to see cross-references, function info, and related data for the current cursor location.

### Changes

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/contextsidebar/ContextSidebarPlugin.java`** (NEW)
  - Plugin that tracks cursor location changes

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/contextsidebar/ContextSidebarProvider.java`** (NEW)
  - Dynamic sidebar showing context-sensitive information:
    - For functions: signature, calling convention, callers, callees, local variables, referenced strings
    - For data: type, cross-references, containing function
    - Updates live as the user navigates

---

## Phase 5: Graph Edge Rendering Fix

### Problem
Ghidra's Function Graph had dead code — edge stroke differentiation (dashed for conditional, thick for unconditional, thin for fallthrough) was implemented but never called.

### Changes

- **`Ghidra/Framework/Graph/src/main/java/ghidra/graph/viewer/edge/VisualEdgeRenderer.java`**
  - Added `getBaseStroke(E e)` protected hook method
  - Modified `drawSimpleEdge()` to use the hook for flow-type differentiation

- **`Ghidra/Features/FunctionGraph/src/main/java/ghidra/app/plugin/core/functiongraph/graph/jung/renderer/FGEdgeRenderer.java`**
  - Renamed `getEdgeStroke()` to `@Override getBaseStroke()` — now actually called by the parent renderer

---

## Phase 6: Theme Polish

Applied consistent dark/light theme improvements across the UI.

---

## Phase 7: Graph System Enhancements

### Changes

- **`Ghidra/Features/FunctionGraph/src/main/java/ghidra/app/plugin/core/functiongraph/graph/FunctionGraphFactory.java`**
  - Added `assignConditionalBranchLabels()` — labels conditional branches with **T** (true) and **F** (false)

- **`Ghidra/Features/GraphFunctionCalls/src/main/java/functioncalls/graph/FcgVertexShapeProvider.java`**
  - Enhanced vertex labels to show function name + address (e.g., `main @ 00401000`)

- **`Ghidra/Features/GraphFunctionCalls/src/main/java/functioncalls/graph/renderer/FcgTooltipProvider.java`**
  - Complete rewrite — rich HTML tooltips showing full function signature, calling convention, size, parameter count, thunk/external indicators

- **`Ghidra/Features/ProgramGraph/src/main/java/ghidra/graph/program/BlockGraphTask.java`**
  - Increased `MAX_SYMBOLS` from 10 to 25
  - Increased `codeLimitPerBlock` from 10 to 20
  - Added flow labels (Cond, Fall, Jump, Call) to edges via `getFlowLabel()`
  - Added address range attributes to vertices

- **`Ghidra/Features/GraphServices/src/main/java/ghidra/graph/visualization/DefaultGraphRenderer.java`**
  - Added `LABEL_WRAP_LENGTH = 120` constant (was hardcoded 80)
  - Added `setEdgeLabelFunction()` call to enable edge labels in jungrapht renderer
  - Added `setEdgeLabelCloseness(0.5f)` for centered label positioning

- **`Ghidra/Features/GraphFunctionCalls/src/main/java/functioncalls/graph/FcgEdge.java`**
  - Added `callCount` field with getter/setter for multi-call edge tracking

- **`Ghidra/Features/GraphFunctionCalls/src/main/java/functioncalls/graph/view/FcgComponent.java`**
  - Added edge label transformer showing x2, x3 etc. for functions called from multiple sites

- **`Ghidra/Features/GraphFunctionCalls/src/main/java/functioncalls/plugin/FcgProvider.java`**
  - Added `computeCallCount()` method using ReferenceManager to count call sites

---

## Phase 8: Documentation, Console & Graph Labels

### 8A: Block/Code Flow Graph Edge Labels

- **`Ghidra/Framework/Graph/src/main/java/ghidra/service/graph/GraphDisplayOptions.java`**
  - Added `edgeLabelOverride` field with `setEdgeLabelOverrideAttributeKey()` and `getEdgeLabel()` methods
  - Increased `maxNodeCount` from 500 to 2000 for large function support

- **`Ghidra/Features/Base/src/main/java/ghidra/graph/ProgramGraphDisplayOptions.java`**
  - Added `setEdgeLabelOverrideAttributeKey("EdgeLabel")` to wire up edge labels
  - Added `setMaxNodeCount(2000)` for program graphs

### 8B: Documentation Plugin

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/documentation/DocumentationPlugin.java`** (NEW)
  - Plugin shell for the documentation system

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/documentation/DocumentationProvider.java`** (NEW)
  - Full ComponentProvider with:
    - JSplitPane: collapsible tree sidebar + HTML content viewer
    - Search bar with real-time tree filtering
    - Styled HTMLEditorKit with CSS for headers, tables, code blocks, tips, warnings
    - Menu actions: Documentation menu with quick-access to all sections
  - 12 categories, 45+ topics

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/documentation/DocumentationContent.java`** (NEW)
  - Static class with all HTML documentation content
  - Covers: Getting Started, Program Tree, Symbols, Data Types, Functions, Decompiler, Graphs, Scripting, Analysis, Navigation, Binhunters Features, Tips (35 tips)

### 8C: Disable Tip of the Day

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/totd/TipOfTheDayPlugin.java`**
  - Changed default `SHOW_TIPS` from `"true"` to `"false"`
  - Added force-migration: detects saved `SHOW_TIPS=true` from previous installs and auto-sets to `false`

- **`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/totd/TipOfTheDayDialog.java`**
  - Changed checkbox default to unchecked

### 8D: Console Welcome Banner

- **`Ghidra/Features/Jython/src/main/java/ghidra/jython/JythonPlugin.java`**
  - Enhanced `welcome()` method with comprehensive banner showing:
    - Available variables (currentProgram, currentAddress, currentSelection, etc.)
    - Quick examples (getFunctionAt, getFunctionCount, getExternalSymbols)
    - Usage tips (help(), dir(), F1)

---

## Phase 9: Binhunters Rebranding

### App Icons
- Converted `Binhunters.jpg` (cyber dragon) to all icon sizes with rounded corners:
  - PNG: 16, 24, 32, 40, 48, 64, 128, 256 pixels
  - ICO: multi-size Windows icon
  - Replaced: `GhidraIcon*.png`, `greenDragon24.png`, `ghidra.ico`

### Splash Screen
- Converted `binhunterswithlogo.jpg` (shield + BINHUNTERS text) to `GHIDRA_Splash.png` (500x500)

### Application Name
- **`Ghidra/application.properties`**: `application.name=Binhunters`
- **`GhidraApplicationInformationDisplayFactory.java`**: Splash title, About dialog title
- **`FrontEndTool.java`**: User Log window title
- **`JythonPlugin.java`**: Python console banner
- **`DocumentationPlugin.java`**, **`DocumentationProvider.java`**, **`DocumentationContent.java`**: All references
- **`CodeBrowser.tool`**: Documentation component title

---

## Files Modified (Complete List)

### Framework Layer
| File | Changes |
|------|---------|
| `Framework/Graph/src/main/java/ghidra/graph/viewer/edge/VisualEdgeRenderer.java` | Added `getBaseStroke()` hook |
| `Framework/Graph/src/main/java/ghidra/service/graph/GraphDisplayOptions.java` | Edge label override, max nodes 2000 |
| `Framework/Gui/src/main/resources/images/GhidraIcon*.png` | Binhunters dragon icons (rounded) |
| `Framework/Project/src/main/java/ghidra/framework/main/FrontEndTool.java` | Rebranded title |

### Features/Base Layer
| File | Changes |
|------|---------|
| `Features/Base/src/main/java/ghidra/app/plugin/core/documentation/DocumentationPlugin.java` | NEW — Documentation plugin |
| `Features/Base/src/main/java/ghidra/app/plugin/core/documentation/DocumentationProvider.java` | NEW — Documentation UI |
| `Features/Base/src/main/java/ghidra/app/plugin/core/documentation/DocumentationContent.java` | NEW — Documentation content |
| `Features/Base/src/main/java/ghidra/app/plugin/core/export/ExportAllDecompiledAction.java` | NEW — Bulk export |
| `Features/Base/src/main/java/ghidra/app/plugin/core/export/ExportAllDecompiledPlugin.java` | NEW — Bulk export plugin |
| `Features/Base/src/main/java/ghidra/app/plugin/core/triage/TriagePlugin.java` | NEW — Triage plugin |
| `Features/Base/src/main/java/ghidra/app/plugin/core/triage/TriageProvider.java` | NEW — Triage panel |
| `Features/Base/src/main/java/ghidra/app/plugin/core/contextsidebar/ContextSidebarPlugin.java` | NEW — Context sidebar |
| `Features/Base/src/main/java/ghidra/app/plugin/core/contextsidebar/ContextSidebarProvider.java` | NEW — Context sidebar UI |
| `Features/Base/src/main/java/ghidra/app/plugin/core/totd/TipOfTheDayPlugin.java` | Disabled tips |
| `Features/Base/src/main/java/ghidra/app/plugin/core/totd/TipOfTheDayDialog.java` | Default unchecked |
| `Features/Base/src/main/java/ghidra/graph/ProgramGraphDisplayOptions.java` | Edge labels, max nodes |
| `Features/Base/src/main/java/ghidra/framework/main/GhidraApplicationInformationDisplayFactory.java` | Rebranded |
| `Features/Base/src/main/resources/images/GHIDRA_Splash.png` | Binhunters splash |
| `Features/Base/src/main/resources/defaultTools/images/greenDragon24.png` | Rounded icon |

### Features/Decompiler
| File | Changes |
|------|---------|
| `Features/Decompiler/src/decompile/cpp/ruleaction.cc` | Cast reduction rules |
| `Features/Decompiler/src/decompile/cpp/ruleaction.hh` | Rule declarations |

### Features/FunctionGraph
| File | Changes |
|------|---------|
| `Features/FunctionGraph/.../FGEdgeRenderer.java` | Fixed dead stroke code |
| `Features/FunctionGraph/.../FunctionGraphFactory.java` | T/F branch labels |

### Features/GraphFunctionCalls
| File | Changes |
|------|---------|
| `Features/GraphFunctionCalls/.../FcgVertexShapeProvider.java` | Address in labels |
| `Features/GraphFunctionCalls/.../FcgTooltipProvider.java` | Rich tooltips |
| `Features/GraphFunctionCalls/.../FcgEdge.java` | Call count field |
| `Features/GraphFunctionCalls/.../FcgComponent.java` | Edge label transformer |
| `Features/GraphFunctionCalls/.../FcgProvider.java` | Call count computation |

### Features/GraphServices
| File | Changes |
|------|---------|
| `Features/GraphServices/.../DefaultGraphRenderer.java` | Edge labels, wrap length |

### Features/ProgramGraph
| File | Changes |
|------|---------|
| `Features/ProgramGraph/.../BlockGraphTask.java` | Flow labels, limits |

### Features/Jython
| File | Changes |
|------|---------|
| `Features/Jython/.../JythonPlugin.java` | Welcome banner |

### Configuration
| File | Changes |
|------|---------|
| `Ghidra/application.properties` | `application.name=Binhunters` |
| `Configurations/.../CodeBrowser.tool` | Documentation plugin registered |
| `RuntimeScripts/Windows/support/ghidra.ico` | Binhunters icon |
