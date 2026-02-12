/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.documentation;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Static class holding all Binhunters documentation content as HTML strings,
 * organized by category. Used by {@link DocumentationProvider} to populate
 * the documentation panel.
 */
public class DocumentationContent {

	private DocumentationContent() {
		// utility class
	}

	/**
	 * Returns the welcome/landing page HTML shown when the documentation panel first opens.
	 * @return welcome page HTML
	 */
	public static String getWelcome() {
		return "<html><body>" +
			"<h1>Binhunters Documentation</h1>" +
			"<p>Welcome to Binhunters, an enhanced build of the Ghidra reverse engineering framework " +
			"designed for faster, more intuitive binary analysis.</p>" +
			"<h2>What's Different</h2>" +
			"<ul>" +
			"<li><b>Triage Panel</b> &mdash; instant binary overview with metadata, sections, strings, and import categories</li>" +
			"<li><b>Context Sidebar</b> &mdash; live context that updates as you navigate</li>" +
			"<li><b>Bulk Export</b> &mdash; export all decompiled code to organized directory structures</li>" +
			"<li><b>Export C Code</b> &mdash; export entire binary as single C file, by namespace, or individual functions</li>" +
			"<li><b>Variable Tracker</b> &mdash; identify shared globals and cross-function data dependencies</li>" +
			"<li><b>Language Detection</b> &mdash; automatically identifies C, C++, ObjC, Swift, Rust, Go</li>" +
			"<li><b>Enhanced Graphs</b> &mdash; flow labels, branch labels (T/F), call-count indicators</li>" +
			"<li><b>Improved Decompiler</b> &mdash; fewer unnecessary casts, better variable names</li>" +
			"<li><b>Interactive Console</b> &mdash; Python REPL with full Ghidra API access</li>" +
			"</ul>" +
			"<h2>Getting Started</h2>" +
			"<p>Select a topic from the tree on the left, or use the search bar above to find information " +
			"about any feature. Categories cover everything from basic navigation to advanced scripting.</p>" +
			"<div class='tip'><b>Tip:</b> Use the Documentation menu in the menu bar for quick access to any section.</div>" +
			"</body></html>";
	}

	/**
	 * Returns all documentation content as a map of "Category/Topic" to HTML strings.
	 * @return ordered map of documentation entries
	 */
	public static Map<String, String> getAllDocumentation() {
		Map<String, String> docs = new LinkedHashMap<>();

		// ============================
		// Getting Started
		// ============================
		docs.put("Getting Started/Overview", html(
			"<h1>Overview</h1>" +
			"<p>Binhunters is a customized build of the NSA's Ghidra reverse engineering framework. " +
			"It adds workflow enhancements, improved graph rendering, an integrated documentation system, " +
			"and a quick-triage panel for faster binary analysis.</p>" +
			"<h2>Core Capabilities</h2>" +
			"<ul>" +
			"<li><b>Disassembly</b> &mdash; converts raw bytes into human-readable assembly instructions</li>" +
			"<li><b>Decompilation</b> &mdash; reconstructs C pseudocode from assembly</li>" +
			"<li><b>Type Recovery</b> &mdash; identifies data types, structures, and function signatures</li>" +
			"<li><b>Cross-References</b> &mdash; tracks where functions/data are used throughout the binary</li>" +
			"<li><b>Graphing</b> &mdash; visualizes control flow, call relationships, and data dependencies</li>" +
			"<li><b>Scripting</b> &mdash; automate analysis with Java or Python scripts</li>" +
			"</ul>" +
			"<h2>Supported Formats</h2>" +
			"<table><tr><th>Format</th><th>Architectures</th></tr>" +
			"<tr><td>ELF</td><td>x86, x86-64, ARM, MIPS, PowerPC, RISC-V</td></tr>" +
			"<tr><td>PE / COFF</td><td>x86, x86-64, ARM</td></tr>" +
			"<tr><td>Mach-O</td><td>x86-64, ARM64 (Apple Silicon)</td></tr>" +
			"<tr><td>Raw Binary</td><td>Any (manual base address required)</td></tr>" +
			"</table>"
		));

		docs.put("Getting Started/Basic Workflow", html(
			"<h1>Basic Workflow</h1>" +
			"<h2>1. Import a Binary</h2>" +
			"<p><code>File &gt; Import File</code> or drag-and-drop onto the project window. " +
			"Ghidra auto-detects the format and architecture.</p>" +
			"<h2>2. Auto-Analysis</h2>" +
			"<p>When prompted, click <b>Analyze</b> (or <code>Analysis &gt; Auto Analyze</code>). " +
			"This runs disassembly, function identification, type propagation, and reference resolution. " +
			"Wait for the progress bar to complete before exploring.</p>" +
			"<h2>3. Explore the Listing</h2>" +
			"<p>The main <b>Listing</b> panel shows disassembled code. Navigate by scrolling, " +
			"pressing <code>G</code> (Go To Address), or double-clicking references.</p>" +
			"<h2>4. Decompile</h2>" +
			"<p>Click on any function in the Listing &mdash; the <b>Decompiler</b> panel (right side) " +
			"shows reconstructed C code. Click tokens in the decompiler to navigate.</p>" +
			"<h2>5. Rename &amp; Annotate</h2>" +
			"<p>Press <code>L</code> to rename symbols, <code>T</code> to change types, " +
			"<code>;</code> to add comments. Good annotations make analysis much faster.</p>" +
			"<h2>6. Graph &amp; Navigate</h2>" +
			"<p>Use <code>Window &gt; Function Graph</code> for control flow, " +
			"<code>Graph &gt; Block Flow</code> for block-level flow, " +
			"<code>Window &gt; Function Call Graph</code> for call trees.</p>"
		));

		docs.put("Getting Started/Keyboard Shortcuts", html(
			"<h1>Keyboard Shortcuts</h1>" +
			"<table>" +
			"<tr><th>Key</th><th>Action</th><th>Description</th></tr>" +
			"<tr><td><code>G</code></td><td>Go To Address</td><td>Jump to any address or label</td></tr>" +
			"<tr><td><code>L</code></td><td>Label / Rename</td><td>Rename the symbol at cursor</td></tr>" +
			"<tr><td><code>T</code></td><td>Set Data Type</td><td>Change the type of a variable or data</td></tr>" +
			"<tr><td><code>;</code></td><td>Set Comment</td><td>Add an end-of-line comment</td></tr>" +
			"<tr><td><code>/</code></td><td>Plate Comment</td><td>Add a plate (block) comment</td></tr>" +
			"<tr><td><code>D</code></td><td>Define Data</td><td>Convert bytes to a data type</td></tr>" +
			"<tr><td><code>C</code></td><td>Disassemble</td><td>Disassemble bytes at cursor</td></tr>" +
			"<tr><td><code>F</code></td><td>Create Function</td><td>Define a function at cursor</td></tr>" +
			"<tr><td><code>Ctrl+Shift+E</code></td><td>Export</td><td>Export program or selection</td></tr>" +
			"<tr><td><code>Ctrl+F</code></td><td>Find</td><td>Search in the current panel</td></tr>" +
			"<tr><td><code>Ctrl+Shift+F</code></td><td>Search Memory</td><td>Search all program memory</td></tr>" +
			"<tr><td><code>Alt+Left</code></td><td>Back</td><td>Navigate backward in history</td></tr>" +
			"<tr><td><code>Alt+Right</code></td><td>Forward</td><td>Navigate forward in history</td></tr>" +
			"<tr><td><code>Space</code></td><td>Toggle Graph</td><td>Switch between Listing and Function Graph</td></tr>" +
			"<tr><td><code>Ctrl+G</code></td><td>Go To Line</td><td>Jump to line in Decompiler</td></tr>" +
			"</table>" +
			"<div class='tip'><b>Tip:</b> Press <code>F1</code> anywhere to see help for the current panel.</div>"
		));

		// ============================
		// Program Tree
		// ============================
		docs.put("Program Tree/Overview", html(
			"<h1>Program Tree</h1>" +
			"<p>The Program Tree (top-left panel) shows the binary's memory layout organized as a hierarchical " +
			"tree of <b>modules</b> and <b>fragments</b>. Each fragment represents a contiguous block of memory.</p>" +
			"<h2>What You See</h2>" +
			"<ul>" +
			"<li>Top-level node = the binary file name</li>" +
			"<li>Child nodes = memory sections (.text, .data, .bss, etc.)</li>" +
			"<li>Click a section to navigate the Listing to that area</li>" +
			"</ul>" +
			"<h2>Multiple Views</h2>" +
			"<p>You can create multiple tree views via <code>right-click &gt; Create New Tree View</code>. " +
			"This is useful for organizing code by subsystem or functionality.</p>" +
			"<div class='tip'><b>Tip:</b> Right-click a fragment to see its address range, size, and permissions (rwx).</div>"
		));

		docs.put("Program Tree/Memory Sections", html(
			"<h1>Memory Sections</h1>" +
			"<p>Compiled binaries are organized into sections with specific purposes:</p>" +
			"<table>" +
			"<tr><th>Section</th><th>Permissions</th><th>Contents</th></tr>" +
			"<tr><td><code>.text</code></td><td>r-x</td><td>Executable code (functions)</td></tr>" +
			"<tr><td><code>.data</code></td><td>rw-</td><td>Initialized global/static variables</td></tr>" +
			"<tr><td><code>.bss</code></td><td>rw-</td><td>Uninitialized globals (zeroed at startup)</td></tr>" +
			"<tr><td><code>.rodata</code></td><td>r--</td><td>Read-only data: strings, constants</td></tr>" +
			"<tr><td><code>.got</code></td><td>rw-</td><td>Global Offset Table (dynamic linking)</td></tr>" +
			"<tr><td><code>.plt</code></td><td>r-x</td><td>Procedure Linkage Table (library call stubs)</td></tr>" +
			"<tr><td><code>.init</code> / <code>.fini</code></td><td>r-x</td><td>Constructor / destructor code</td></tr>" +
			"<tr><td><code>.dynsym</code></td><td>r--</td><td>Dynamic symbol table</td></tr>" +
			"<tr><td><code>.dynstr</code></td><td>r--</td><td>Dynamic string table</td></tr>" +
			"</table>" +
			"<div class='warning'><b>Note:</b> Section names vary by platform. Mach-O uses __TEXT/__DATA segments with " +
			"sections like __text, __cstring, __objc_methname.</div>"
		));

		docs.put("Program Tree/Fragments", html(
			"<h1>Fragments</h1>" +
			"<p>Fragments are Ghidra's way of organizing code/data within the program tree. " +
			"Each fragment maps to a contiguous address range.</p>" +
			"<h2>Working with Fragments</h2>" +
			"<ul>" +
			"<li><b>Create:</b> Right-click in the tree &gt; Create Fragment</li>" +
			"<li><b>Move code:</b> Drag addresses from the Listing into a fragment</li>" +
			"<li><b>Rename:</b> Right-click a fragment &gt; Rename</li>" +
			"<li><b>View range:</b> Right-click &gt; Properties shows the address range</li>" +
			"</ul>" +
			"<p>Fragments are useful for organizing large binaries by subsystem (e.g., networking code, " +
			"crypto routines, UI handling).</p>"
		));

		// ============================
		// Symbols
		// ============================
		docs.put("Symbols/Overview", html(
			"<h1>Symbols</h1>" +
			"<p>Symbols are <b>names attached to addresses</b>. They are the primary way you understand " +
			"a binary &mdash; transforming raw addresses like <code>0x401000</code> into meaningful names " +
			"like <code>main</code> or <code>processPacket</code>.</p>" +
			"<h2>Symbol Sources</h2>" +
			"<ul>" +
			"<li><b>Debug symbols</b> &mdash; from debug info (DWARF, PDB) if not stripped</li>" +
			"<li><b>Import/Export tables</b> &mdash; dynamic linking metadata</li>" +
			"<li><b>Auto-analysis</b> &mdash; Ghidra generates <code>FUN_XXXXX</code>, <code>DAT_XXXXX</code> names</li>" +
			"<li><b>User-defined</b> &mdash; names you assign during analysis (press <code>L</code>)</li>" +
			"</ul>" +
			"<h2>Symbol Tree</h2>" +
			"<p>The <b>Symbol Tree</b> panel (left side) organizes all symbols into categories: " +
			"Imports, Exports, Functions, Labels, Classes, Namespaces.</p>" +
			"<div class='tip'><b>Tip:</b> The <b>Symbol Table</b> (<code>Window &gt; Symbol Table</code>) " +
			"shows a flat, filterable list of ALL symbols &mdash; great for searching.</div>"
		));

		docs.put("Symbols/Imports", html(
			"<h1>Imports</h1>" +
			"<p>Import symbols represent external functions and data that the binary uses from " +
			"shared libraries (DLLs, .so, .dylib).</p>" +
			"<h2>Reading Imports</h2>" +
			"<p>Imports tell you what capabilities the binary relies on:</p>" +
			"<table>" +
			"<tr><th>Category</th><th>Example Imports</th><th>Indicates</th></tr>" +
			"<tr><td>Networking</td><td>socket, connect, send, recv</td><td>Network communication</td></tr>" +
			"<tr><td>File I/O</td><td>fopen, read, write, unlink</td><td>File operations</td></tr>" +
			"<tr><td>Memory</td><td>malloc, mmap, VirtualAlloc</td><td>Dynamic memory usage</td></tr>" +
			"<tr><td>Process</td><td>fork, exec, CreateProcess</td><td>Process manipulation</td></tr>" +
			"<tr><td>Crypto</td><td>AES_encrypt, SHA256_Update</td><td>Encryption/hashing</td></tr>" +
			"<tr><td>Registry</td><td>RegOpenKeyEx, RegSetValueEx</td><td>Windows registry access</td></tr>" +
			"</table>" +
			"<div class='tip'><b>Tip:</b> The Binhunters <b>Triage Panel</b> automatically categorizes " +
			"imports and shows counts per category.</div>"
		));

		docs.put("Symbols/Exports", html(
			"<h1>Exports</h1>" +
			"<p>Export symbols are functions or data that the binary makes available to other modules. " +
			"In shared libraries, exports are the library's public API.</p>" +
			"<ul>" +
			"<li><b>Executables</b> usually export very little (sometimes just <code>main</code> or entry point)</li>" +
			"<li><b>Libraries (.dll/.so/.dylib)</b> export many functions that other programs call</li>" +
			"<li><b>Ordinal exports</b> (Windows DLLs) may not have names &mdash; only numbers</li>" +
			"</ul>"
		));

		docs.put("Symbols/Functions", html(
			"<h1>Functions</h1>" +
			"<p>Functions are subroutines identified by analysis or defined manually. They are the " +
			"primary unit of code organization in a binary.</p>" +
			"<h2>Function Names</h2>" +
			"<ul>" +
			"<li><code>main</code>, <code>processPacket</code> &mdash; named (from symbols or user annotation)</li>" +
			"<li><code>FUN_00401000</code> &mdash; auto-generated (address-based, needs investigation)</li>" +
			"<li><code>thunk_FUN_00401000</code> &mdash; thunk/stub that jumps to another function</li>" +
			"</ul>" +
			"<h2>Function Actions</h2>" +
			"<table>" +
			"<tr><th>Action</th><th>How</th></tr>" +
			"<tr><td>Create function</td><td>Press <code>F</code> at start of code</td></tr>" +
			"<tr><td>Rename</td><td>Press <code>L</code> on function name</td></tr>" +
			"<tr><td>Edit signature</td><td>Right-click &gt; Edit Function Signature</td></tr>" +
			"<tr><td>View callers</td><td>Right-click &gt; References &gt; Show References To</td></tr>" +
			"<tr><td>View callees</td><td>Right-click &gt; References &gt; Show References From</td></tr>" +
			"</table>"
		));

		docs.put("Symbols/Labels", html(
			"<h1>Labels</h1>" +
			"<p>Labels are names assigned to specific addresses that are not function entry points. " +
			"They mark important locations in code or data.</p>" +
			"<ul>" +
			"<li><b>Code labels</b> &mdash; branch targets, loop heads, switch cases</li>" +
			"<li><b>Data labels</b> &mdash; string constants, global variables, vtable entries</li>" +
			"<li>Press <code>L</code> on any address to add/edit a label</li>" +
			"<li>Auto-labels like <code>LAB_00401050</code> indicate branch targets found by analysis</li>" +
			"</ul>"
		));

		docs.put("Symbols/Classes", html(
			"<h1>Classes</h1>" +
			"<p>Ghidra can recover class hierarchies from C++ and Objective-C binaries. Classes appear " +
			"in the Symbol Tree under the <b>Classes</b> folder.</p>" +
			"<ul>" +
			"<li><b>Virtual function tables (vtables)</b> help identify class methods</li>" +
			"<li><b>RTTI (Run-Time Type Information)</b> provides class names and inheritance</li>" +
			"<li><b>Objective-C metadata</b> is automatically parsed for method names and protocols</li>" +
			"</ul>" +
			"<div class='tip'><b>Tip:</b> Use <code>Window &gt; Symbol Table</code> and filter by " +
			"namespace to see all methods in a specific class.</div>"
		));

		docs.put("Symbols/Namespaces", html(
			"<h1>Namespaces</h1>" +
			"<p>Namespaces group related symbols hierarchically, similar to C++ namespaces or Java packages. " +
			"Every function belongs to a namespace (the Global namespace by default).</p>" +
			"<ul>" +
			"<li>Classes are a type of namespace</li>" +
			"<li>Libraries can have their own namespace</li>" +
			"<li>Right-click a symbol &gt; Set Namespace to organize manually</li>" +
			"</ul>"
		));

		// ============================
		// Data Types
		// ============================
		docs.put("Data Types/Overview", html(
			"<h1>Data Types</h1>" +
			"<p>The Data Type Manager (bottom-left panel) organizes all known types. Correct typing is " +
			"crucial for readable decompiler output &mdash; telling Ghidra that a parameter is " +
			"<code>char*</code> vs <code>int</code> dramatically changes the decompiled code.</p>" +
			"<h2>Type Sources</h2>" +
			"<ul>" +
			"<li><b>Built-in</b> &mdash; standard C types (int, char, void, etc.)</li>" +
			"<li><b>Program types</b> &mdash; types recovered from the binary's debug info</li>" +
			"<li><b>Archive types</b> &mdash; imported from .gdt type archives (Windows API, POSIX, etc.)</li>" +
			"<li><b>User-defined</b> &mdash; types you create during analysis</li>" +
			"</ul>"
		));

		docs.put("Data Types/Built-in Types", html(
			"<h1>Built-in Types</h1>" +
			"<table>" +
			"<tr><th>Type</th><th>Size</th><th>Description</th></tr>" +
			"<tr><td><code>byte</code></td><td>1</td><td>Unsigned 8-bit value</td></tr>" +
			"<tr><td><code>char</code></td><td>1</td><td>Character (signed or unsigned, platform-dependent)</td></tr>" +
			"<tr><td><code>short</code></td><td>2</td><td>16-bit integer</td></tr>" +
			"<tr><td><code>int</code></td><td>4</td><td>32-bit integer</td></tr>" +
			"<tr><td><code>long</code></td><td>4 or 8</td><td>Platform-dependent integer</td></tr>" +
			"<tr><td><code>longlong</code></td><td>8</td><td>64-bit integer</td></tr>" +
			"<tr><td><code>float</code></td><td>4</td><td>32-bit IEEE 754 floating point</td></tr>" +
			"<tr><td><code>double</code></td><td>8</td><td>64-bit IEEE 754 floating point</td></tr>" +
			"<tr><td><code>pointer</code></td><td>4 or 8</td><td>Address pointer (32-bit or 64-bit)</td></tr>" +
			"<tr><td><code>void</code></td><td>0</td><td>No type / unknown</td></tr>" +
			"</table>" +
			"<div class='tip'><b>Tip:</b> Use <code>uint</code>, <code>ulong</code>, etc. for unsigned variants.</div>"
		));

		docs.put("Data Types/Structures", html(
			"<h1>Structures</h1>" +
			"<p>Structures (structs) group related fields at specific offsets. Defining structs is one of " +
			"the most impactful things you can do for decompiler readability.</p>" +
			"<h2>Creating a Structure</h2>" +
			"<ol>" +
			"<li>In the Data Type Manager, right-click a folder &gt; <b>New &gt; Structure</b></li>" +
			"<li>Name the structure and set its size</li>" +
			"<li>Add fields by clicking in the structure editor and setting offsets, types, and names</li>" +
			"<li>Apply to a variable in the decompiler: right-click &gt; Retype Variable</li>" +
			"</ol>" +
			"<h2>Auto Structure</h2>" +
			"<p>Right-click a variable in the Decompiler &gt; <b>Auto Create Structure</b> &mdash; Ghidra " +
			"analyzes how the variable is used and creates field definitions automatically.</p>" +
			"<div class='tip'><b>Tip:</b> This is extremely powerful for understanding objects and buffers. " +
			"Start with Auto Create Structure, then refine field names and types manually.</div>"
		));

		docs.put("Data Types/Enums", html(
			"<h1>Enumerations</h1>" +
			"<p>Enums map numeric constants to meaningful names. Applying an enum type makes " +
			"magic numbers readable (e.g., <code>3</code> becomes <code>SOCK_RAW</code>).</p>" +
			"<h2>Creating an Enum</h2>" +
			"<ol>" +
			"<li>Data Type Manager &gt; right-click folder &gt; <b>New &gt; Enum</b></li>" +
			"<li>Add name-value pairs</li>" +
			"<li>Apply as a type to variables or function parameters</li>" +
			"</ol>"
		));

		docs.put("Data Types/Creating Types", html(
			"<h1>Creating Custom Types</h1>" +
			"<h2>CParser</h2>" +
			"<p>For complex types, use the C parser: Data Type Manager &gt; right-click &gt; " +
			"<b>Parse C Source</b>. Paste a C header file and Ghidra will create all the types.</p>" +
			"<h2>Type Archives (.gdt)</h2>" +
			"<p>Import pre-made type archives for common APIs:</p>" +
			"<ul>" +
			"<li><code>windows_vs12_32.gdt</code> / <code>windows_vs12_64.gdt</code> &mdash; Windows API types</li>" +
			"<li><code>generic_clib.gdt</code> &mdash; Standard C library types</li>" +
			"<li><code>mac_osx.gdt</code> &mdash; macOS / iOS frameworks</li>" +
			"</ul>" +
			"<p>Open via: <code>File &gt; Open Data Type Archive</code></p>"
		));

		// ============================
		// Functions
		// ============================
		docs.put("Functions/Overview", html(
			"<h1>Functions</h1>" +
			"<p>Functions are the fundamental unit of code organization. Ghidra's analysis identifies function " +
			"boundaries, calling conventions, parameters, return types, and local variables.</p>" +
			"<h2>Key Panels</h2>" +
			"<ul>" +
			"<li><b>Function Window</b> (<code>Window &gt; Functions</code>) &mdash; filterable list of all functions</li>" +
			"<li><b>Decompiler</b> &mdash; shows C pseudocode for the selected function</li>" +
			"<li><b>Function Graph</b> (<code>Window &gt; Function Graph</code>) &mdash; visual control flow</li>" +
			"</ul>"
		));

		docs.put("Functions/Function List", html(
			"<h1>Function List</h1>" +
			"<p>Open the Function Window: <code>Window &gt; Functions</code></p>" +
			"<h2>Filtering</h2>" +
			"<p>The filter bar at the bottom lets you search by name, address, size, and more. " +
			"Use this to quickly find functions of interest.</p>" +
			"<h2>Useful Columns</h2>" +
			"<ul>" +
			"<li><b>Name</b> &mdash; function name (FUN_XXXXX = auto-generated, needs investigation)</li>" +
			"<li><b>Size</b> &mdash; larger functions are often more complex and interesting</li>" +
			"<li><b>Signature</b> &mdash; full prototype with parameters and return type</li>" +
			"<li><b>Calling Convention</b> &mdash; how parameters are passed</li>" +
			"</ul>" +
			"<div class='tip'><b>Tip:</b> Sort by Size (descending) to find the largest, most complex functions first.</div>"
		));

		docs.put("Functions/Signatures", html(
			"<h1>Function Signatures</h1>" +
			"<p>A function signature defines: return type, name, and parameter types/names.</p>" +
			"<h2>Editing Signatures</h2>" +
			"<p>Right-click a function name &gt; <b>Edit Function Signature</b> (or press <code>F</code> on the name).</p>" +
			"<ul>" +
			"<li>Set return type (void, int, char*, struct pointer, etc.)</li>" +
			"<li>Add/remove parameters with correct types</li>" +
			"<li>Name parameters descriptively (buffer, length, flags, etc.)</li>" +
			"<li>Changes immediately improve decompiler output</li>" +
			"</ul>"
		));

		docs.put("Functions/Calling Conventions", html(
			"<h1>Calling Conventions</h1>" +
			"<p>Calling conventions define how parameters are passed and who cleans the stack.</p>" +
			"<table>" +
			"<tr><th>Convention</th><th>Platform</th><th>Parameters</th><th>Stack Cleanup</th></tr>" +
			"<tr><td><code>cdecl</code></td><td>x86</td><td>Stack (right-to-left)</td><td>Caller</td></tr>" +
			"<tr><td><code>stdcall</code></td><td>Win32 API</td><td>Stack (right-to-left)</td><td>Callee</td></tr>" +
			"<tr><td><code>fastcall</code></td><td>x86</td><td>ECX, EDX, then stack</td><td>Callee</td></tr>" +
			"<tr><td><code>thiscall</code></td><td>C++ x86</td><td>ECX=this, rest on stack</td><td>Callee</td></tr>" +
			"<tr><td><code>System V AMD64</code></td><td>Linux/macOS x64</td><td>RDI, RSI, RDX, RCX, R8, R9</td><td>Caller</td></tr>" +
			"<tr><td><code>MS x64</code></td><td>Windows x64</td><td>RCX, RDX, R8, R9</td><td>Caller</td></tr>" +
			"<tr><td><code>AAPCS</code></td><td>ARM</td><td>R0-R3</td><td>Caller</td></tr>" +
			"</table>" +
			"<div class='warning'><b>Important:</b> If the decompiler shows wrong parameter values, the calling " +
			"convention may be set incorrectly. Fix it via Edit Function Signature &gt; Calling Convention dropdown.</div>"
		));

		docs.put("Functions/Stack Frames", html(
			"<h1>Stack Frames</h1>" +
			"<p>Each function's stack frame contains local variables, saved registers, and parameters. " +
			"View via: right-click function &gt; <b>Function &gt; Edit Stack Frame</b>.</p>" +
			"<h2>Stack Layout (x86-64 typical)</h2>" +
			"<pre>" +
			"  Higher addresses\n" +
			"  +------------------+\n" +
			"  | Return address   |  (pushed by CALL)\n" +
			"  +------------------+\n" +
			"  | Saved RBP        |  (frame pointer)\n" +
			"  +------------------+\n" +
			"  | Local var 1      |\n" +
			"  | Local var 2      |\n" +
			"  | ...              |\n" +
			"  +------------------+\n" +
			"  Lower addresses (RSP)\n" +
			"</pre>"
		));

		// ============================
		// Decompiler
		// ============================
		docs.put("Decompiler/Overview", html(
			"<h1>Decompiler</h1>" +
			"<p>The Decompiler converts machine code back into C pseudocode. This is the most powerful " +
			"analysis tool in Ghidra &mdash; it lets you understand binary logic without reading assembly.</p>" +
			"<h2>How It Works</h2>" +
			"<ol>" +
			"<li>Lifts assembly instructions to an intermediate representation (P-code)</li>" +
			"<li>Applies simplification rules to eliminate redundant operations</li>" +
			"<li>Recovers control flow structures (if/else, loops, switch)</li>" +
			"<li>Assigns types and variable names</li>" +
			"<li>Emits C pseudocode</li>" +
			"</ol>" +
			"<h2>Binhunters Improvements</h2>" +
			"<ul>" +
			"<li>Fewer unnecessary type casts between int/uint of same size</li>" +
			"<li>Better variable naming: loop counters use i/j/k, malloc returns use descriptive names</li>" +
			"<li>More aggressive simplification of zero/sign extensions</li>" +
			"</ul>"
		));

		docs.put("Decompiler/Reading Output", html(
			"<h1>Reading Decompiler Output</h1>" +
			"<h2>Common Patterns</h2>" +
			"<ul>" +
			"<li><code>uVar1</code>, <code>iVar2</code> &mdash; auto-named variables (u=unsigned, i=int, l=long, p=pointer)</li>" +
			"<li><code>param_1</code>, <code>param_2</code> &mdash; function parameters (rename for clarity!)</li>" +
			"<li><code>local_18</code> &mdash; local variable at stack offset 0x18</li>" +
			"<li><code>(int)</code>, <code>(long)</code> &mdash; type casts (Binhunters reduces unnecessary ones)</li>" +
			"</ul>" +
			"<h2>Improving Output</h2>" +
			"<ol>" +
			"<li><b>Retype variables:</b> Right-click &gt; Retype Variable (or press <code>Ctrl+L</code>)</li>" +
			"<li><b>Rename variables:</b> Right-click &gt; Rename Variable (or press <code>L</code>)</li>" +
			"<li><b>Apply structs:</b> Right-click &gt; Auto Create Structure on pointer variables</li>" +
			"<li><b>Fix function signatures:</b> Correct parameter types propagate through calls</li>" +
			"</ol>" +
			"<div class='tip'><b>Tip:</b> Start by fixing types at the top (function parameters), and changes " +
			"cascade down through the decompiled code automatically.</div>"
		));

		docs.put("Decompiler/Navigation", html(
			"<h1>Decompiler Navigation</h1>" +
			"<ul>" +
			"<li><b>Click a function call</b> &mdash; navigates to that function's decompilation</li>" +
			"<li><b>Click a variable</b> &mdash; highlights all uses of that variable</li>" +
			"<li><b>Double-click a token</b> &mdash; navigates to its definition</li>" +
			"<li><b>Right-click &gt; References</b> &mdash; show all cross-references to/from this location</li>" +
			"<li><b>Middle-click (or Ctrl+click)</b> &mdash; navigate and decompile</li>" +
			"<li><b>Alt+Left/Right</b> &mdash; navigate backward/forward in history</li>" +
			"</ul>"
		));

		docs.put("Decompiler/Export", html(
			"<h1>Export Decompiled Code</h1>" +
			"<h2>Export All Decompiled (Binhunters Feature)</h2>" +
			"<p>Use <code>File &gt; Export All Decompiled Code</code> to export every function's " +
			"decompiled C code to an organized directory structure:</p>" +
			"<pre>" +
			"output/\n" +
			"  binary_name/\n" +
			"    functions/           # All functions by name\n" +
			"    by_namespace/        # Grouped by class/namespace\n" +
			"    by_category/         # System vs user code\n" +
			"    imports/             # Import summary\n" +
			"    strings/             # String listing\n" +
			"    types/               # Type definitions (.h)\n" +
			"    summary.txt          # Overview statistics\n" +
			"</pre>" +
			"<h2>Single Function Export</h2>" +
			"<p>In the Decompiler, right-click &gt; <b>Copy</b> to copy the C code for the current function.</p>"
		));

		// ============================
		// Graphs
		// ============================
		docs.put("Graphs/Overview", html(
			"<h1>Graphs</h1>" +
			"<p>Binhunters provides several graph types for visual analysis. Each shows a different " +
			"perspective on the binary's structure.</p>" +
			"<table>" +
			"<tr><th>Graph</th><th>Menu</th><th>Shows</th><th>Best For</th></tr>" +
			"<tr><td>Function Graph</td><td>Window &gt; Function Graph</td><td>Basic blocks within one function</td><td>Understanding control flow</td></tr>" +
			"<tr><td>Block Flow</td><td>Graph &gt; Block Flow</td><td>Block-level flow (jungrapht)</td><td>Larger-scale flow overview</td></tr>" +
			"<tr><td>Code Flow</td><td>Graph &gt; Code Flow</td><td>Instruction-level flow</td><td>Detailed execution paths</td></tr>" +
			"<tr><td>Call Graph</td><td>Window &gt; Function Call Graph</td><td>Function call relationships</td><td>Understanding call hierarchies</td></tr>" +
			"<tr><td>Data Flow</td><td>Graph &gt; Data</td><td>Data reference relationships</td><td>Tracking data usage</td></tr>" +
			"</table>"
		));

		docs.put("Graphs/Function Graph", html(
			"<h1>Function Graph</h1>" +
			"<p>Open: <code>Window &gt; Function Graph</code> (or press <code>Space</code> to toggle)</p>" +
			"<p>Shows the control flow graph of the currently selected function. Each box (vertex) is a " +
			"<b>basic block</b> &mdash; a straight-line sequence of instructions with one entry and one exit.</p>" +
			"<h2>Edge Types (Binhunters Enhanced)</h2>" +
			"<table>" +
			"<tr><th>Style</th><th>Meaning</th></tr>" +
			"<tr><td>Dashed + <b>T</b></td><td>Conditional branch taken (true)</td></tr>" +
			"<tr><td>Dashed + <b>F</b></td><td>Conditional branch not taken (false/fallthrough)</td></tr>" +
			"<tr><td>Thick solid</td><td>Unconditional jump</td></tr>" +
			"<tr><td>Thin solid</td><td>Fallthrough (sequential execution)</td></tr>" +
			"</table>" +
			"<h2>Interactions</h2>" +
			"<ul>" +
			"<li>Double-click a block to navigate the Listing there</li>" +
			"<li>Scroll to zoom in/out</li>" +
			"<li>Right-click &gt; Layout to change graph layout algorithm</li>" +
			"<li>Group vertices by selecting and right-clicking &gt; Group</li>" +
			"</ul>"
		));

		docs.put("Graphs/Block Flow Graph", html(
			"<h1>Block Flow Graph</h1>" +
			"<p>Open: <code>Graph &gt; Block Flow</code></p>" +
			"<p>Shows block-level control flow using the jungrapht rendering engine. This provides a " +
			"higher-level overview than the Function Graph.</p>" +
			"<h2>Edge Labels (Binhunters Enhanced)</h2>" +
			"<ul>" +
			"<li><b>Cond</b> &mdash; Conditional branch</li>" +
			"<li><b>Fall</b> &mdash; Fallthrough (sequential)</li>" +
			"<li><b>Jump</b> &mdash; Unconditional jump</li>" +
			"<li><b>Call</b> &mdash; Function call</li>" +
			"</ul>" +
			"<h2>Navigation</h2>" +
			"<ul>" +
			"<li>Click a vertex to select it</li>" +
			"<li>Double-click to navigate to that block in the Listing</li>" +
			"<li>Use the satellite view (mini-map) for orientation in large graphs</li>" +
			"<li>Right-click for layout and export options</li>" +
			"</ul>"
		));

		docs.put("Graphs/Code Flow Graph", html(
			"<h1>Code Flow Graph</h1>" +
			"<p>Open: <code>Graph &gt; Code Flow</code></p>" +
			"<p>Similar to Block Flow but shows individual instructions in the vertices, giving you " +
			"instruction-level detail of the execution flow.</p>" +
			"<div class='tip'><b>Tip:</b> Use Code Flow Graph when you need to trace exact instruction " +
			"sequences. Use Block Flow for a higher-level overview.</div>"
		));

		docs.put("Graphs/Call Graph", html(
			"<h1>Call Graph</h1>" +
			"<p>Open: <code>Window &gt; Function Call Graph</code></p>" +
			"<p>Shows which functions call which. The currently selected function is in the center, with " +
			"callers above and callees below.</p>" +
			"<h2>Binhunters Enhancements</h2>" +
			"<ul>" +
			"<li><b>Vertex labels</b> show function name + address (e.g., <code>main @ 00401000</code>)</li>" +
			"<li><b>Tooltips</b> show full function signature, calling convention, size, and parameter count</li>" +
			"<li><b>Edge labels</b> show call counts: <code>&times;2</code> means the caller calls that function from 2 different sites</li>" +
			"</ul>" +
			"<h2>Expanding the Graph</h2>" +
			"<p>Double-click a vertex to expand its callers/callees. The graph grows incrementally " +
			"so you can explore call chains without overwhelming the display.</p>"
		));

		docs.put("Graphs/Data Flow", html(
			"<h1>Data Flow Graph</h1>" +
			"<p>Open: <code>Graph &gt; Data</code></p>" +
			"<p>Shows data reference relationships &mdash; which functions read from or write to which addresses.</p>" +
			"<h2>Edge Types</h2>" +
			"<ul>" +
			"<li><b>Read</b> &mdash; function reads from the data address</li>" +
			"<li><b>Write</b> &mdash; function writes to the data address</li>" +
			"<li><b>Read/Write</b> &mdash; function both reads and writes</li>" +
			"</ul>"
		));

		// ============================
		// Scripting
		// ============================
		docs.put("Scripting/Overview", html(
			"<h1>Scripting</h1>" +
			"<p>Ghidra supports automation through multiple scripting languages:</p>" +
			"<table>" +
			"<tr><th>Language</th><th>How to Access</th><th>Best For</th></tr>" +
			"<tr><td>Java</td><td>Script Manager</td><td>Full API access, best performance, complex analysis</td></tr>" +
			"<tr><td>Jython (Python 2)</td><td>Window &gt; Python</td><td>Quick interactive exploration, simple scripts</td></tr>" +
			"<tr><td>PyGhidra (Python 3)</td><td>Window &gt; Python (if configured)</td><td>Modern Python, external libraries</td></tr>" +
			"</table>" +
			"<p>All scripts have access to the same Ghidra API, which provides programmatic access to " +
			"everything you can do in the GUI and more.</p>"
		));

		docs.put("Scripting/Interactive Console", html(
			"<h1>Interactive Console</h1>" +
			"<p>Open: <code>Window &gt; Python</code></p>" +
			"<p>The Python console gives you an interactive REPL (Read-Eval-Print Loop) with full access " +
			"to the Ghidra API. Type code and see results immediately.</p>" +
			"<h2>Pre-loaded Variables</h2>" +
			"<table>" +
			"<tr><th>Variable</th><th>Type</th><th>Description</th></tr>" +
			"<tr><td><code>currentProgram</code></td><td>Program</td><td>The currently open binary</td></tr>" +
			"<tr><td><code>currentAddress</code></td><td>Address</td><td>Where the cursor is in the Listing</td></tr>" +
			"<tr><td><code>currentSelection</code></td><td>AddressSetView</td><td>Currently selected address range</td></tr>" +
			"<tr><td><code>currentHighlight</code></td><td>AddressSetView</td><td>Currently highlighted range</td></tr>" +
			"<tr><td><code>monitor</code></td><td>TaskMonitor</td><td>For progress tracking and cancellation</td></tr>" +
			"<tr><td><code>state</code></td><td>GhidraState</td><td>Current tool state</td></tr>" +
			"</table>" +
			"<h2>Quick Examples</h2>" +
			"<pre>" +
			"# Get program name\n" +
			"print(currentProgram.getName())\n" +
			"\n" +
			"# Get function at cursor\n" +
			"func = getFunctionAt(currentAddress)\n" +
			"print(func.getSignature())\n" +
			"\n" +
			"# Count all functions\n" +
			"fm = currentProgram.getFunctionManager()\n" +
			"print('Total functions: %d' % fm.getFunctionCount())\n" +
			"\n" +
			"# List first 10 functions\n" +
			"for f in fm.getFunctions(True):\n" +
			"    print('%s @ %s' % (f.getName(), f.getEntryPoint()))\n" +
			"</pre>" +
			"<div class='tip'><b>Tip:</b> Use <code>help(object)</code> to see its API and <code>dir(object)</code> " +
			"to list all available methods and properties.</div>"
		));

		docs.put("Scripting/Writing Scripts", html(
			"<h1>Writing Scripts</h1>" +
			"<h2>Script Manager</h2>" +
			"<p>Open: <code>Window &gt; Script Manager</code> (or click the script icon in the toolbar)</p>" +
			"<p>The Script Manager lists all available scripts, organized by category. You can run, edit, " +
			"or create new scripts from here.</p>" +
			"<h2>Creating a New Script</h2>" +
			"<ol>" +
			"<li>In Script Manager, click the <b>New Script</b> icon</li>" +
			"<li>Choose language (Java or Python)</li>" +
			"<li>Scripts extend <code>GhidraScript</code> and implement <code>run()</code></li>" +
			"</ol>" +
			"<h2>Script Template (Java)</h2>" +
			"<pre>" +
			"import ghidra.app.script.GhidraScript;\n" +
			"\n" +
			"public class MyScript extends GhidraScript {\n" +
			"    public void run() throws Exception {\n" +
			"        // Your code here\n" +
			"        println(\"Program: \" +\n" +
			"            currentProgram.getName());\n" +
			"    }\n" +
			"}\n" +
			"</pre>" +
			"<h2>Script Directories</h2>" +
			"<p>Add custom script directories via Script Manager &gt; <b>Manage Script Directories</b> icon.</p>"
		));

		docs.put("Scripting/API Reference", html(
			"<h1>API Reference</h1>" +
			"<p>Key manager objects available through <code>currentProgram</code>:</p>" +
			"<table>" +
			"<tr><th>Manager</th><th>Access</th><th>Purpose</th></tr>" +
			"<tr><td>FunctionManager</td><td><code>getFunctionManager()</code></td><td>Iterate, create, modify functions</td></tr>" +
			"<tr><td>SymbolTable</td><td><code>getSymbolTable()</code></td><td>Find, create, rename symbols</td></tr>" +
			"<tr><td>ReferenceManager</td><td><code>getReferenceManager()</code></td><td>Cross-references (xrefs to/from)</td></tr>" +
			"<tr><td>DataTypeManager</td><td><code>getDataTypeManager()</code></td><td>Types, structures, enums</td></tr>" +
			"<tr><td>Listing</td><td><code>getListing()</code></td><td>Instructions, data, comments</td></tr>" +
			"<tr><td>Memory</td><td><code>getMemory()</code></td><td>Read bytes, sections, permissions</td></tr>" +
			"<tr><td>AddressFactory</td><td><code>getAddressFactory()</code></td><td>Parse address strings</td></tr>" +
			"<tr><td>BookmarkManager</td><td><code>getBookmarkManager()</code></td><td>Create and manage bookmarks</td></tr>" +
			"</table>" +
			"<h2>Flat API (GhidraScript convenience methods)</h2>" +
			"<table>" +
			"<tr><th>Method</th><th>Description</th></tr>" +
			"<tr><td><code>getFunctionAt(addr)</code></td><td>Get function at specific address</td></tr>" +
			"<tr><td><code>getDataAt(addr)</code></td><td>Get defined data at address</td></tr>" +
			"<tr><td><code>getReferencesTo(addr)</code></td><td>All references pointing to address</td></tr>" +
			"<tr><td><code>getReferencesFrom(addr)</code></td><td>All references from this address</td></tr>" +
			"<tr><td><code>toAddr(string)</code></td><td>Convert string to Address</td></tr>" +
			"<tr><td><code>getBytes(addr, len)</code></td><td>Read bytes from memory</td></tr>" +
			"<tr><td><code>createLabel(addr, name)</code></td><td>Create a label at address</td></tr>" +
			"<tr><td><code>createFunction(addr, name)</code></td><td>Create a function</td></tr>" +
			"</table>"
		));

		docs.put("Scripting/Common Workflows", html(
			"<h1>Common Scripting Workflows</h1>" +
			"<h2>Iterate All Functions</h2>" +
			"<pre>" +
			"fm = currentProgram.getFunctionManager()\n" +
			"for func in fm.getFunctions(True):\n" +
			"    print('%s at %s (size: %d)' % (\n" +
			"        func.getName(),\n" +
			"        func.getEntryPoint(),\n" +
			"        func.getBody().getNumAddresses()))\n" +
			"</pre>" +
			"<h2>Find All Strings</h2>" +
			"<pre>" +
			"from ghidra.program.util import DefinedDataIterator\n" +
			"for s in DefinedDataIterator.definedStrings(currentProgram):\n" +
			"    print('%s: %s' % (s.getAddress(), s.getValue()))\n" +
			"</pre>" +
			"<h2>Find Cross-References to a Function</h2>" +
			"<pre>" +
			"func = getFunctionAt(currentAddress)\n" +
			"refs = getReferencesTo(func.getEntryPoint())\n" +
			"for ref in refs:\n" +
			"    caller = getFunctionContaining(ref.getFromAddress())\n" +
			"    if caller:\n" +
			"        print('Called from: %s' % caller.getName())\n" +
			"</pre>" +
			"<h2>Rename Auto-Named Functions</h2>" +
			"<pre>" +
			"fm = currentProgram.getFunctionManager()\n" +
			"count = 0\n" +
			"for func in fm.getFunctions(True):\n" +
			"    if func.getName().startswith('FUN_'):\n" +
			"        count += 1\n" +
			"print('Auto-named functions: %d' % count)\n" +
			"</pre>"
		));

		// ============================
		// Analysis
		// ============================
		docs.put("Analysis/Overview", html(
			"<h1>Analysis</h1>" +
			"<p>Ghidra's analysis engine automatically processes the binary to identify code, data, " +
			"functions, types, and references. This runs automatically on import and can be re-run " +
			"at any time.</p>"
		));

		docs.put("Analysis/Auto Analysis", html(
			"<h1>Auto Analysis</h1>" +
			"<p>Auto-analysis runs a pipeline of analyzers that work together:</p>" +
			"<ol>" +
			"<li><b>Disassembly</b> &mdash; converts bytes to instructions starting from known entry points</li>" +
			"<li><b>Function Detection</b> &mdash; identifies function boundaries from call targets and patterns</li>" +
			"<li><b>Reference Analysis</b> &mdash; resolves data and code references</li>" +
			"<li><b>Type Propagation</b> &mdash; propagates types through function calls and data flow</li>" +
			"<li><b>Decompiler Parameter ID</b> &mdash; uses decompilation to identify function parameters</li>" +
			"<li><b>Symbol Resolution</b> &mdash; resolves import/export symbols from libraries</li>" +
			"</ol>" +
			"<p>Re-run: <code>Analysis &gt; Auto Analyze</code></p>" +
			"<div class='tip'><b>Tip:</b> Wait for auto-analysis to fully complete before starting manual analysis. " +
			"Watch the progress bar at the bottom right.</div>"
		));

		docs.put("Analysis/One-Shot Analyzers", html(
			"<h1>One-Shot Analyzers</h1>" +
			"<p>Run individual analyzers on demand via <code>Analysis &gt; One Shot</code>:</p>" +
			"<ul>" +
			"<li><b>Aggressive Instruction Finder</b> &mdash; finds code that wasn't reached by normal flow</li>" +
			"<li><b>Create Address Tables</b> &mdash; identifies switch tables and function pointer arrays</li>" +
			"<li><b>Decompiler Switch Analysis</b> &mdash; resolves complex switch statements</li>" +
			"<li><b>Non-Returning Functions</b> &mdash; marks functions like exit(), abort() as non-returning</li>" +
			"</ul>"
		));

		docs.put("Analysis/Options", html(
			"<h1>Analysis Options</h1>" +
			"<p>Configure via <code>Analysis &gt; Auto Analyze</code> before clicking Analyze, " +
			"or <code>Edit &gt; Tool Options &gt; Analysis</code>.</p>" +
			"<h2>Key Options</h2>" +
			"<ul>" +
			"<li><b>Decompiler Parameter ID</b> &mdash; Enable for better function signatures (slower)</li>" +
			"<li><b>Shared Return Calls</b> &mdash; Resolve tail-call optimizations</li>" +
			"<li><b>Stack Analysis</b> &mdash; Track stack pointer changes for local variables</li>" +
			"<li><b>ASCII Strings</b> &mdash; Automatically define string data</li>" +
			"</ul>"
		));

		// ============================
		// Navigation
		// ============================
		docs.put("Navigation/Overview", html(
			"<h1>Navigation</h1>" +
			"<p>Efficient navigation is key to productive reverse engineering. Ghidra provides " +
			"multiple ways to move through a binary quickly.</p>"
		));

		docs.put("Navigation/Search", html(
			"<h1>Search</h1>" +
			"<h2>String Search</h2>" +
			"<p><code>Search &gt; For Strings</code> &mdash; finds all defined and undefined strings.</p>" +
			"<h2>Memory Search</h2>" +
			"<p><code>Search &gt; Memory</code> (Ctrl+Shift+F) &mdash; search for byte patterns, strings, " +
			"or regular expressions across all memory.</p>" +
			"<h2>Instruction Pattern Search</h2>" +
			"<p><code>Search &gt; For Instruction Patterns</code> &mdash; find specific instruction sequences " +
			"(e.g., all <code>CALL</code> instructions, or <code>MOV RAX, [RBP+offset]</code> patterns).</p>" +
			"<h2>Label Search</h2>" +
			"<p><code>Search &gt; Label</code> &mdash; find labels/symbols matching a pattern.</p>"
		));

		docs.put("Navigation/Bookmarks", html(
			"<h1>Bookmarks</h1>" +
			"<p>Bookmarks mark important locations for quick return during analysis.</p>" +
			"<h2>Creating Bookmarks</h2>" +
			"<ul>" +
			"<li><code>Ctrl+D</code> &mdash; create a bookmark at the current address</li>" +
			"<li>Set category and description for organization</li>" +
			"<li>View all: <code>Window &gt; Bookmarks</code></li>" +
			"</ul>" +
			"<h2>Bookmark Types</h2>" +
			"<ul>" +
			"<li><b>Note</b> &mdash; general analysis notes</li>" +
			"<li><b>Info</b> &mdash; informational markers</li>" +
			"<li><b>Warning</b> &mdash; suspicious or problematic areas</li>" +
			"<li><b>Error</b> &mdash; analysis errors or issues</li>" +
			"</ul>"
		));

		docs.put("Navigation/Cross References", html(
			"<h1>Cross References (Xrefs)</h1>" +
			"<p>Cross-references show where code or data is referenced from. They are essential for " +
			"understanding how the binary's components connect.</p>" +
			"<h2>Viewing Xrefs</h2>" +
			"<ul>" +
			"<li>Right-click &gt; <b>References &gt; Show References To</b> (who uses this?)</li>" +
			"<li>Right-click &gt; <b>References &gt; Show References From</b> (what does this use?)</li>" +
			"<li>Xrefs appear as small labels in the Listing (e.g., <code>XREF[3]</code>)</li>" +
			"</ul>" +
			"<h2>Reference Types</h2>" +
			"<table>" +
			"<tr><th>Type</th><th>Symbol</th><th>Meaning</th></tr>" +
			"<tr><td>Call</td><td><code>c</code></td><td>Function call instruction</td></tr>" +
			"<tr><td>Jump</td><td><code>j</code></td><td>Branch/jump target</td></tr>" +
			"<tr><td>Read</td><td><code>r</code></td><td>Data read access</td></tr>" +
			"<tr><td>Write</td><td><code>w</code></td><td>Data write access</td></tr>" +
			"<tr><td>Pointer</td><td><code>*</code></td><td>Pointer/address reference</td></tr>" +
			"</table>" +
			"<div class='tip'><b>Tip:</b> High xref counts indicate important functions or data. " +
			"A function called from 50 places is likely a utility function worth understanding.</div>"
		));

		// ============================
		// Binhunters Features
		// ============================
		docs.put("Binhunters Features/Triage Panel", html(
			"<h1>Triage Panel</h1>" +
			"<p>The Triage Panel provides an instant overview of any binary, visible as a tab next to the Decompiler.</p>" +
			"<h2>What It Shows</h2>" +
			"<ul>" +
			"<li><b>Binary Metadata</b> &mdash; name, format (ELF/PE/Mach-O), architecture, endianness, entry point</li>" +
			"<li><b>Section Map</b> &mdash; visual bar showing .text, .data, .bss sizes and permissions</li>" +
			"<li><b>Function Statistics</b> &mdash; total count, named vs auto-named, average size</li>" +
			"<li><b>Interesting Strings</b> &mdash; URLs, file paths, error messages, crypto-related strings</li>" +
			"<li><b>Import Categories</b> &mdash; imports grouped by purpose (network, file, crypto, process)</li>" +
			"</ul>" +
			"<div class='tip'><b>Tip:</b> Check the Triage Panel first when opening a new binary. It gives you " +
			"a quick sense of what the binary does before diving into code.</div>"
		));

		docs.put("Binhunters Features/Context Sidebar", html(
			"<h1>Context Sidebar</h1>" +
			"<p>The Context Sidebar dynamically updates to show relevant information for whatever " +
			"you're currently looking at. It appears on the right side of the Listing.</p>" +
			"<h2>Context for Functions</h2>" +
			"<ul>" +
			"<li>Function signature and calling convention</li>" +
			"<li>Incoming xrefs (callers)</li>" +
			"<li>Outgoing calls (callees)</li>" +
			"<li>Local variables with types</li>" +
			"<li>Referenced strings</li>" +
			"</ul>" +
			"<h2>Context for Variables/Data</h2>" +
			"<ul>" +
			"<li>All cross-references to/from</li>" +
			"<li>Data type information</li>" +
			"<li>Containing function</li>" +
			"</ul>"
		));

		docs.put("Binhunters Features/Bulk Export", html(
			"<h1>Bulk Export</h1>" +
			"<p>Export all decompiled functions at once via <code>File &gt; Export All Decompiled Code</code>.</p>" +
			"<h2>Output Structure</h2>" +
			"<ul>" +
			"<li><b>functions/</b> &mdash; flat listing of all functions</li>" +
			"<li><b>by_namespace/</b> &mdash; organized by class/namespace</li>" +
			"<li><b>by_category/</b> &mdash; user functions vs auto-generated vs stubs</li>" +
			"<li><b>imports/</b> &mdash; import summary by library</li>" +
			"<li><b>strings/</b> &mdash; all defined strings with addresses</li>" +
			"<li><b>types/</b> &mdash; type definitions as a C header</li>" +
			"<li><b>summary.txt</b> &mdash; binary overview and statistics</li>" +
			"</ul>"
		));

		docs.put("Binhunters Features/Enhanced Graphs", html(
			"<h1>Enhanced Graphs</h1>" +
			"<p>Binhunters improves all graph types with better visual information:</p>" +
			"<h2>Function Graph</h2>" +
			"<ul>" +
			"<li>Working edge strokes (dashed, thick, thin) based on flow type</li>" +
			"<li><b>T/F labels</b> on conditional branches showing true/false paths</li>" +
			"</ul>" +
			"<h2>Block Flow / Code Flow Graphs</h2>" +
			"<ul>" +
			"<li><b>Edge labels</b> showing Cond/Fall/Jump/Call for each connection</li>" +
			"<li>Increased block limits (25 symbols, 20 instructions per block)</li>" +
			"<li>Wider label wrapping (120 chars) for better readability</li>" +
			"</ul>" +
			"<h2>Call Graph</h2>" +
			"<ul>" +
			"<li>Function name + address in vertex labels</li>" +
			"<li>Rich tooltips with full signature, calling convention, size, parameters</li>" +
			"<li><b>&times;N</b> edge labels for multi-call edges (e.g., &times;3 means 3 call sites)</li>" +
			"</ul>"
		));

		docs.put("Binhunters Features/Improved Decompiler", html(
			"<h1>Improved Decompiler</h1>" +
			"<p>Binhunters's decompiler produces cleaner, more readable output:</p>" +
			"<h2>Reduced Casts</h2>" +
			"<ul>" +
			"<li>Suppresses unnecessary int/uint casts of the same size in arithmetic contexts</li>" +
			"<li>More aggressively hides implied zero/sign extensions</li>" +
			"<li>New simplification rules eliminate redundant cast operations</li>" +
			"</ul>" +
			"<h2>Better Variable Names</h2>" +
			"<ul>" +
			"<li>Loop counters named <code>i</code>, <code>j</code>, <code>k</code> instead of <code>local_XX</code></li>" +
			"<li>Return values incorporate function names (e.g., <code>mallocResult</code>)</li>" +
			"<li>Function parameters use type-based naming when possible</li>" +
			"</ul>"
		));

		docs.put("Binhunters Features/Variable Tracker", html(
			"<h1>Variable Tracker</h1>" +
			"<p>The Variable Tracker panel (<code>Analysis &gt; Variable Tracker</code>) identifies " +
			"cross-function variable usage and shared data dependencies.</p>" +
			"<h2>Three Views</h2>" +
			"<h3>Global Variables Tab</h3>" +
			"<p>Scans all global variables and shows which functions reference each one. " +
			"Sorted by usage count &mdash; variables used by many functions appear first.</p>" +
			"<ul>" +
			"<li><span style='color:red'>Red</span> = used by 10+ functions (critical shared state)</li>" +
			"<li><span style='color:orange'>Orange</span> = used by 5-9 functions (important)</li>" +
			"<li><span style='color:blue'>Blue</span> = used by 2-4 functions (notable)</li>" +
			"</ul>" +
			"<h3>Current Function Tab</h3>" +
			"<p>Shows detailed variable information for the currently selected function:</p>" +
			"<ul>" +
			"<li>Parameters with call-site information (who passes values)</li>" +
			"<li>Local variables</li>" +
			"<li>Global data accessed (with other functions that share access)</li>" +
			"<li>Strings referenced</li>" +
			"<li>Data connections showing which other functions share variables</li>" +
			"</ul>" +
			"<h3>Shared Data Tab</h3>" +
			"<p>Shows variables used by 2 or more functions. These are the key data dependencies " +
			"that connect different parts of the program.</p>" +
			"<div class='tip'><b>Tip:</b> Use the Variable Tracker to quickly identify global configuration, " +
			"state machines, and shared buffers that multiple functions operate on.</div>"
		));

		docs.put("Binhunters Features/Export C Code", html(
			"<h1>Export C Code</h1>" +
			"<p>Binhunters provides multiple ways to export decompiled C code:</p>" +
			"<h2>Export C Code... (New)</h2>" +
			"<p>Access via the decompiler's menu. Provides three modes:</p>" +
			"<ul>" +
			"<li><b>Entire Binary (single file)</b> &mdash; exports all functions into one <code>.c</code> file " +
			"with type definitions, forward declarations, and organized function implementations</li>" +
			"<li><b>By Namespace</b> &mdash; creates one <code>.c</code> file per namespace/class, plus a " +
			"shared <code>types.h</code> header</li>" +
			"<li><b>Current Function</b> &mdash; quick export of just the function you're looking at</li>" +
			"</ul>" +
			"<h2>Export All Decompiled Code</h2>" +
			"<p>The original bulk export creates a full directory structure with functions, namespaces, " +
			"categories, imports, strings, and types.</p>" +
			"<h2>Language Detection</h2>" +
			"<p>The export automatically detects the source language (C, C++, Objective-C, Swift, Rust, Go) " +
			"by analyzing symbol patterns, section names, and import libraries.</p>"
		));

		docs.put("Binhunters Features/Language Detection", html(
			"<h1>Language Detection</h1>" +
			"<p>Binhunters can identify the likely source language of a binary.</p>" +
			"<h2>How It Works</h2>" +
			"<p>The detector analyzes:</p>" +
			"<ul>" +
			"<li><b>Symbol patterns</b> &mdash; C++ name mangling (_Z prefixes, :: operators), ObjC messaging " +
			"patterns, Swift/Rust/Go naming conventions</li>" +
			"<li><b>Section names</b> &mdash; __objc_*, __swift*, .gopclntab</li>" +
			"<li><b>Binary format</b> &mdash; DEX (Android), .class (Java), .NET CLR</li>" +
			"<li><b>Import libraries</b> &mdash; language-specific runtime libraries</li>" +
			"</ul>" +
			"<h2>Supported Languages</h2>" +
			"<table>" +
			"<tr><th>Language</th><th>Key Indicators</th></tr>" +
			"<tr><td>C</td><td>Default when no other language detected</td></tr>" +
			"<tr><td>C++</td><td>Mangled names (_Z*), virtual tables, std:: symbols</td></tr>" +
			"<tr><td>Objective-C</td><td>objc_msgSend, +[Class method], _OBJC_ symbols</td></tr>" +
			"<tr><td>Swift</td><td>_$s prefixes, Swift runtime symbols</td></tr>" +
			"<tr><td>Rust</td><td>$LT$/$GT$ encoding, __rust_ symbols, core.. prefixes</td></tr>" +
			"<tr><td>Go</td><td>go.* symbols, runtime.*, .gopclntab section</td></tr>" +
			"</table>" +
			"<p>The Triage Panel shows the detected language with confidence level " +
			"(high/medium/low).</p>"
		));

		// ============================
		// Tips
		// ============================
		docs.put("Tips/All Tips", html(
			"<h1>Tips &amp; Tricks</h1>" +
			"<ol>" +
			"<li><b>G for Go To:</b> Press <code>G</code> to jump to any address, label, or function by name.</li>" +
			"<li><b>L for Label:</b> Press <code>L</code> to rename anything. Good names are the foundation of analysis.</li>" +
			"<li><b>; for Comment:</b> Add end-of-line comments to record your analysis notes inline.</li>" +
			"<li><b>Ctrl+Shift+F for Memory Search:</b> Search all program memory for byte patterns or strings.</li>" +
			"<li><b>Auto Create Structure:</b> Right-click a pointer variable in the Decompiler and select " +
			"Auto Create Structure to auto-detect struct fields.</li>" +
			"<li><b>Middle-Click Navigation:</b> Middle-click (or Ctrl+click) in the Decompiler to follow references.</li>" +
			"<li><b>Alt+Left/Right:</b> Navigate backward and forward in your history, like a web browser.</li>" +
			"<li><b>Space toggles Function Graph:</b> Press Space to switch between Listing and Function Graph views.</li>" +
			"<li><b>Highlight variables:</b> Click a variable in the Decompiler to highlight all its uses.</li>" +
			"<li><b>Script Manager:</b> Press the Script Manager icon in the toolbar for hundreds of built-in scripts.</li>" +
			"<li><b>Right-click for everything:</b> Right-click context menus contain most analysis actions.</li>" +
			"<li><b>Xref counts matter:</b> A function with many incoming references is likely important.</li>" +
			"<li><b>Fix types at the top:</b> Correcting parameter types in a function signature improves all callers' decompilation.</li>" +
			"<li><b>Use type archives:</b> Import .gdt files for Windows, Linux, or macOS API types.</li>" +
			"<li><b>Bookmark suspicious code:</b> Use Ctrl+D to bookmark areas that need further investigation.</li>" +
			"<li><b>Python console:</b> Open Window &gt; Python for interactive Ghidra API access.</li>" +
			"<li><b>Function Window:</b> Use Window &gt; Functions and sort by size to find the most complex functions.</li>" +
			"<li><b>Entropy view:</b> High entropy sections may be encrypted or compressed data.</li>" +
			"<li><b>String search first:</b> Search &gt; For Strings often reveals the binary's purpose immediately.</li>" +
			"<li><b>Check imports:</b> The import list tells you what OS features the binary uses.</li>" +
			"<li><b>Define arrays:</b> If you see repeated data, select the range and define it as an array type.</li>" +
			"<li><b>CParser for headers:</b> Paste C struct definitions into Data Type Manager &gt; Parse C Source.</li>" +
			"<li><b>Diff programs:</b> Use Tools &gt; Program Differences to compare two binary versions.</li>" +
			"<li><b>Export to C:</b> Use the Bulk Export feature to get all decompiled code at once.</li>" +
			"<li><b>Graph for understanding flow:</b> When a function is confusing, view its Function Graph for visual control flow.</li>" +
			"<li><b>T/F on branches:</b> In the Function Graph, T and F labels show which path is the true/false branch.</li>" +
			"<li><b>Rename decompiler variables:</b> Click a variable in the Decompiler, press L, and give it a meaningful name.</li>" +
			"<li><b>Block Flow for overview:</b> Use Graph &gt; Block Flow for a high-level function flow overview.</li>" +
			"<li><b>Call Graph to explore:</b> The Function Call Graph shows calling relationships &mdash; great for understanding code organization.</li>" +
			"<li><b>Triage Panel first:</b> Check the Triage Panel when opening a new binary for instant overview.</li>" +
			"<li><b>Undo is your friend:</b> Ctrl+Z undoes most operations. Don't be afraid to experiment.</li>" +
			"<li><b>Save often:</b> Ctrl+S saves your project. Ghidra also auto-saves periodically.</li>" +
			"<li><b>Multiple tools:</b> Open the same binary in multiple CodeBrowser windows for side-by-side analysis.</li>" +
			"<li><b>Conditional breakpoints in Debugger:</b> The Ghidra debugger supports conditional breakpoints for dynamic analysis.</li>" +
			"<li><b>Watch tool tips:</b> Hover over tokens in the Decompiler for quick type and value information.</li>" +
			"</ol>"
		));

		return docs;
	}

	private static String html(String body) {
		return "<html><body>" + body + "</body></html>";
	}
}
