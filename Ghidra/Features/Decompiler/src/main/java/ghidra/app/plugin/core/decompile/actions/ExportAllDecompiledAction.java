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
package ghidra.app.plugin.core.decompile.actions;

import java.io.*;
import java.util.*;

import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.DecompileConfigurer;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Action to export all decompiled functions and supporting data (strings, imports, types)
 * to an organized directory structure on disk.
 *
 * Output structure:
 *   output/
 *   +-- binary_name/
 *       +-- functions/              (flat listing, all functions by name_address.c)
 *       +-- by_namespace/           (grouped by class/namespace)
 *       +-- by_category/            (user_functions, auto_functions, stubs, entry)
 *       +-- imports/imports_summary.txt
 *       +-- strings/strings.txt
 *       +-- types/types.h
 *       +-- summary.txt
 */
public class ExportAllDecompiledAction extends AbstractDecompilerAction {

	private static final String LAST_USED_EXPORT_DIR = "last.used.decompiler.export.all.dir";

	public ExportAllDecompiledAction() {
		super("Export All Decompiled");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ToolBarExport"));
		setMenuBarData(
			new MenuData(new String[] { "Export All Decompiled Code..." }, "xExport"));
		setDescription("Export all decompiled functions to organized directory structure");
	}

	private File chooseOutputDirectory(DecompilerActionContext context) {
		String lastDir = Preferences.getProperty(LAST_USED_EXPORT_DIR);
		GhidraFileChooser chooser = new GhidraFileChooser(context.getDecompilerPanel());
		chooser.setTitle("Choose Export Directory");
		chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		chooser.setApproveButtonText("Export Here");
		if (lastDir != null) {
			chooser.setSelectedFile(new File(lastDir));
		}
		File dir = chooser.getSelectedFile();
		chooser.dispose();
		if (dir != null) {
			Preferences.setProperty(LAST_USED_EXPORT_DIR, dir.getAbsolutePath());
			Preferences.store();
		}
		return dir;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return context.getProgram() != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		File outputDir = chooseOutputDirectory(context);
		if (outputDir == null) {
			return;
		}

		Program program = context.getProgram();
		String binaryName = sanitizeFilename(program.getName());
		File baseDir = new File(outputDir, binaryName);

		ExportTask task = new ExportTask(program, baseDir, context);
		context.getTool().execute(task, 500);
	}

	/**
	 * Background task that performs the full export.
	 */
	private class ExportTask extends Task {
		private final Program program;
		private final File baseDir;
		private final DecompilerActionContext context;

		ExportTask(Program program, File baseDir, DecompilerActionContext context) {
			super("Exporting All Decompiled Code", true, true, true);
			this.program = program;
			this.baseDir = baseDir;
			this.context = context;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			try {
				doRun(monitor);
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				Msg.error(ExportAllDecompiledAction.class, "Export failed", e);
			}
		}

		private void doRun(TaskMonitor monitor) throws Exception {
			// Create directory structure
			File functionsDir = new File(baseDir, "functions");
			File byNamespaceDir = new File(baseDir, "by_namespace");
			File byCategoryDir = new File(baseDir, "by_category");
			File importsDir = new File(baseDir, "imports");
			File stringsDir = new File(baseDir, "strings");
			File typesDir = new File(baseDir, "types");

			File userFuncsDir = new File(byCategoryDir, "user_functions");
			File autoFuncsDir = new File(byCategoryDir, "auto_functions");
			File stubsDir = new File(byCategoryDir, "stubs");
			File entryDir = new File(byCategoryDir, "entry");

			functionsDir.mkdirs();
			byNamespaceDir.mkdirs();
			userFuncsDir.mkdirs();
			autoFuncsDir.mkdirs();
			stubsDir.mkdirs();
			entryDir.mkdirs();
			importsDir.mkdirs();
			stringsDir.mkdirs();
			typesDir.mkdirs();

			FunctionManager funcMgr = program.getFunctionManager();
			int totalFunctions = funcMgr.getFunctionCount();
			monitor.initialize(totalFunctions + 3); // +3 for strings, imports, types
			monitor.setMessage("Decompiling all functions...");

			// Phase 1: Decompile all functions in parallel
			List<FunctionResult> results = decompileAllFunctions(program, monitor);

			if (monitor.isCancelled()) {
				return;
			}

			// Phase 2: Write function files to all three directory views
			monitor.setMessage("Writing function files...");
			int exported = 0;
			int failed = 0;

			for (FunctionResult result : results) {
				if (monitor.isCancelled()) {
					return;
				}

				if (result == null || result.cCode == null || result.cCode.isEmpty()) {
					failed++;
					continue;
				}

				String funcName = result.functionName;
				String addressStr = result.address;
				String flatFilename = sanitizeFilename(funcName) + "_" + addressStr + ".c";

				// 1. Flat listing: functions/name_address.c
				writeFile(new File(functionsDir, flatFilename), result.cCode);

				// 2. By namespace: by_namespace/NamespaceName/funcName.c
				String namespace = result.namespace;
				File nsDir;
				if (namespace == null || namespace.isEmpty() ||
					namespace.equals("Global") || namespace.equals(program.getName())) {
					nsDir = new File(byNamespaceDir, "_ungrouped");
				}
				else {
					nsDir = new File(byNamespaceDir, sanitizeFilename(namespace));
				}
				nsDir.mkdirs();
				String nsFilename = sanitizeFilename(funcName) + ".c";
				// Handle duplicate names within same namespace by appending address
				File nsFile = new File(nsDir, nsFilename);
				if (nsFile.exists()) {
					nsFilename = sanitizeFilename(funcName) + "_" + addressStr + ".c";
					nsFile = new File(nsDir, nsFilename);
				}
				writeFile(nsFile, result.cCode);

				// 3. By category: categorize into user/auto/stubs/entry
				File categoryDir = categorizeFunction(result, userFuncsDir, autoFuncsDir,
					stubsDir, entryDir);
				writeFile(new File(categoryDir, flatFilename), result.cCode);

				exported++;
				monitor.incrementProgress(1);
			}

			if (monitor.isCancelled()) {
				return;
			}

			// Phase 3: Export strings
			monitor.setMessage("Exporting strings...");
			int stringCount = exportStrings(program, new File(stringsDir, "strings.txt"));
			monitor.incrementProgress(1);

			if (monitor.isCancelled()) {
				return;
			}

			// Phase 4: Export imports
			monitor.setMessage("Exporting imports...");
			int importCount =
				exportImports(program, new File(importsDir, "imports_summary.txt"));
			monitor.incrementProgress(1);

			if (monitor.isCancelled()) {
				return;
			}

			// Phase 5: Export types
			monitor.setMessage("Exporting types...");
			int typeCount = exportTypes(program, new File(typesDir, "types.h"));
			monitor.incrementProgress(1);

			// Phase 6: Write summary
			writeSummary(new File(baseDir, "summary.txt"), program, exported, failed,
				stringCount, importCount, typeCount);

			Msg.info(ExportAllDecompiledAction.class,
				"Export complete: " + exported + " functions, " + stringCount +
					" strings, " + importCount + " imports, " + typeCount + " types -> " +
					baseDir.getAbsolutePath());
		}
	}

	// -----------------------------------------------------------------------
	// Parallel decompilation
	// -----------------------------------------------------------------------

	private static List<FunctionResult> decompileAllFunctions(Program program,
			TaskMonitor monitor) throws InterruptedException, Exception {

		DecompileConfigurer configurer = decompiler -> {
			DecompileOptions options = new DecompileOptions();
			decompiler.setOptions(options);
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(false);
		};

		DecompilerCallback<FunctionResult> callback =
			new DecompilerCallback<FunctionResult>(program, configurer) {
				@Override
				public FunctionResult process(DecompileResults results, TaskMonitor mon)
						throws Exception {
					Function func = results.getFunction();
					if (func == null) {
						return null;
					}

					String cCode = null;
					if (results.decompileCompleted()) {
						DecompiledFunction df = results.getDecompiledFunction();
						if (df != null) {
							cCode = df.getC();
						}
					}

					String funcName = func.getName();
					String address =
						func.getEntryPoint().toString().replace(":", "_");
					Namespace ns = func.getParentNamespace();
					String namespace = (ns != null && !ns.isGlobal()) ? ns.getName(true) : "";
					boolean isThunk = func.isThunk();
					boolean isExternal = func.isExternal();
					boolean isAutoName = funcName.startsWith("FUN_") ||
						funcName.startsWith("thunk_FUN_");
					boolean isEntry = func.getProgram()
						.getSymbolTable()
						.isExternalEntryPoint(func.getEntryPoint());
					boolean isStub = isThunk || isExternal ||
						funcName.startsWith("_objc_msgSend") ||
						funcName.startsWith("__stub_") ||
						(ns != null && ns.getName().contains("stub"));

					return new FunctionResult(funcName, address, namespace, cCode,
						isAutoName, isStub, isEntry);
				}
			};

		try {
			FunctionManager funcMgr = program.getFunctionManager();
			List<Function> allFunctions = new ArrayList<>();
			FunctionIterator iter = funcMgr.getFunctions(true);
			while (iter.hasNext()) {
				allFunctions.add(iter.next());
			}

			return ParallelDecompiler.decompileFunctions(callback, allFunctions, monitor);
		}
		finally {
			callback.dispose();
		}
	}

	// -----------------------------------------------------------------------
	// Data holder for decompilation results
	// -----------------------------------------------------------------------

	private static class FunctionResult {
		final String functionName;
		final String address;
		final String namespace;
		final String cCode;
		final boolean isAutoName;
		final boolean isStub;
		final boolean isEntry;

		FunctionResult(String functionName, String address, String namespace, String cCode,
				boolean isAutoName, boolean isStub, boolean isEntry) {
			this.functionName = functionName;
			this.address = address;
			this.namespace = namespace;
			this.cCode = cCode;
			this.isAutoName = isAutoName;
			this.isStub = isStub;
			this.isEntry = isEntry;
		}
	}

	// -----------------------------------------------------------------------
	// Function categorization
	// -----------------------------------------------------------------------

	private File categorizeFunction(FunctionResult result, File userDir, File autoDir,
			File stubsDir, File entryDir) {
		if (result.isEntry) {
			return entryDir;
		}
		if (result.isStub) {
			return stubsDir;
		}
		if (result.isAutoName) {
			return autoDir;
		}
		return userDir;
	}

	// -----------------------------------------------------------------------
	// String export
	// -----------------------------------------------------------------------

	private int exportStrings(Program program, File outputFile) throws IOException {
		int count = 0;
		try (PrintWriter writer = new PrintWriter(new FileOutputStream(outputFile))) {
			writer.println("# Defined Strings");
			writer.println("# Extracted from: " + program.getName());
			writer.println("# Format: ADDRESS | STRING | REFERENCING_FUNCTIONS");
			writer.println("#");
			writer.println();

			for (Data stringData : DefinedStringIterator.forProgram(program)) {
				Address addr = stringData.getAddress();
				Object value = stringData.getValue();
				String stringValue = (value != null) ? value.toString() : "<null>";

				// Escape newlines and tabs for clean output
				stringValue = stringValue.replace("\n", "\\n")
					.replace("\r", "\\r")
					.replace("\t", "\\t");

				// Find referencing functions
				ReferenceManager refMgr = program.getReferenceManager();
				ReferenceIterator references = refMgr.getReferencesTo(addr);
				Set<String> refFuncNames = new LinkedHashSet<>();
				while (references.hasNext()) {
					Reference ref = references.next();
					Function refFunc =
						program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
					if (refFunc != null) {
						refFuncNames.add(refFunc.getName());
					}
				}

				String refStr = refFuncNames.isEmpty() ? "(none)" :
					String.join(", ", refFuncNames);

				writer.printf("%s | %s | %s%n", addr.toString(), stringValue, refStr);
				count++;
			}

			writer.println();
			writer.println("# Total strings: " + count);
		}
		return count;
	}

	// -----------------------------------------------------------------------
	// Import export
	// -----------------------------------------------------------------------

	private int exportImports(Program program, File outputFile) throws IOException {
		int count = 0;
		try (PrintWriter writer = new PrintWriter(new FileOutputStream(outputFile))) {
			writer.println("# Import Summary");
			writer.println("# Extracted from: " + program.getName());
			writer.println();

			SymbolTable symbolTable = program.getSymbolTable();

			// Group external symbols by library
			Map<String, List<String>> byLibrary = new TreeMap<>();

			SymbolIterator externalSymbols = symbolTable.getExternalSymbols();
			while (externalSymbols.hasNext()) {
				Symbol sym = externalSymbols.next();
				Namespace parent = sym.getParentNamespace();
				String libName = "UNKNOWN";
				if (parent != null && !parent.isGlobal()) {
					libName = parent.getName();
				}

				String entry = sym.getName();
				// Add type info if it's a function
				ExternalLocation extLoc =
					program.getExternalManager().getExternalLocation(sym);
				if (extLoc != null && extLoc.getFunction() != null) {
					Function extFunc = extLoc.getFunction();
					entry = extFunc.getPrototypeString(false, false);
				}

				byLibrary.computeIfAbsent(libName, k -> new ArrayList<>()).add(entry);
				count++;
			}

			// Write grouped by library
			for (Map.Entry<String, List<String>> entry : byLibrary.entrySet()) {
				writer.println("## " + entry.getKey() +
					" (" + entry.getValue().size() + " symbols)");
				writer.println();
				for (String sym : entry.getValue()) {
					writer.println("  " + sym);
				}
				writer.println();
			}

			writer.println("# Total imports: " + count);
		}
		return count;
	}

	// -----------------------------------------------------------------------
	// Type export
	// -----------------------------------------------------------------------

	private int exportTypes(Program program, File outputFile) throws IOException {
		int count = 0;
		try (PrintWriter writer = new PrintWriter(new FileOutputStream(outputFile))) {
			writer.println("/* Type definitions extracted from: " + program.getName() + " */");
			writer.println();

			DataTypeManager dtm = program.getDataTypeManager();

			// Export enums
			writer.println("/* ==================== Enumerations ==================== */");
			writer.println();
			Iterator<DataType> allTypes = dtm.getAllDataTypes();
			List<DataType> enums = new ArrayList<>();
			List<DataType> structs = new ArrayList<>();
			List<DataType> unions = new ArrayList<>();
			List<DataType> typedefs = new ArrayList<>();
			List<DataType> funcDefs = new ArrayList<>();

			while (allTypes.hasNext()) {
				DataType dt = allTypes.next();
				// Skip built-in types
				if (dt.getDataTypeManager() != dtm) {
					continue;
				}
				if (dt instanceof ghidra.program.model.data.Enum) {
					enums.add(dt);
				}
				else if (dt instanceof Structure) {
					structs.add(dt);
				}
				else if (dt instanceof Union) {
					unions.add(dt);
				}
				else if (dt instanceof TypeDef) {
					typedefs.add(dt);
				}
				else if (dt instanceof FunctionDefinition) {
					funcDefs.add(dt);
				}
			}

			// Write enums
			for (DataType dt : enums) {
				ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum) dt;
				writer.println("typedef enum " + sanitizeCName(e.getName()) + " {");
				String[] names = e.getNames();
				for (int i = 0; i < names.length; i++) {
					long val = e.getValue(names[i]);
					writer.print("    " + names[i] + " = 0x" + Long.toHexString(val));
					if (i < names.length - 1) {
						writer.print(",");
					}
					writer.println();
				}
				writer.println("} " + sanitizeCName(e.getName()) + ";");
				writer.println();
				count++;
			}

			// Write forward declarations for structs/unions
			writer.println("/* ==================== Forward Declarations ==================== */");
			writer.println();
			for (DataType dt : structs) {
				writer.println(
					"typedef struct " + sanitizeCName(dt.getName()) + " " +
						sanitizeCName(dt.getName()) + ";");
			}
			for (DataType dt : unions) {
				writer.println(
					"typedef union " + sanitizeCName(dt.getName()) + " " +
						sanitizeCName(dt.getName()) + ";");
			}
			writer.println();

			// Write struct definitions
			writer.println("/* ==================== Structures ==================== */");
			writer.println();
			for (DataType dt : structs) {
				Structure s = (Structure) dt;
				writer.println("struct " + sanitizeCName(s.getName()) + " {");
				for (DataTypeComponent comp : s.getDefinedComponents()) {
					String fieldName =
						(comp.getFieldName() != null) ? comp.getFieldName() : "field_" +
							Integer.toHexString(comp.getOffset());
					writer.println(
						"    " + comp.getDataType().getDisplayName() + " " + fieldName +
							";  /* offset: 0x" + Integer.toHexString(comp.getOffset()) +
							", size: " + comp.getLength() + " */");
				}
				writer.println("};  /* sizeof = " + s.getLength() + " */");
				writer.println();
				count++;
			}

			// Write union definitions
			writer.println("/* ==================== Unions ==================== */");
			writer.println();
			for (DataType dt : unions) {
				Union u = (Union) dt;
				writer.println("union " + sanitizeCName(u.getName()) + " {");
				for (DataTypeComponent comp : u.getDefinedComponents()) {
					String fieldName =
						(comp.getFieldName() != null) ? comp.getFieldName() : "member_" +
							comp.getOrdinal();
					writer.println(
						"    " + comp.getDataType().getDisplayName() + " " + fieldName + ";");
				}
				writer.println("};  /* sizeof = " + u.getLength() + " */");
				writer.println();
				count++;
			}

			// Write typedefs
			writer.println("/* ==================== Typedefs ==================== */");
			writer.println();
			for (DataType dt : typedefs) {
				TypeDef td = (TypeDef) dt;
				writer.println("typedef " + td.getBaseDataType().getDisplayName() + " " +
					sanitizeCName(td.getName()) + ";");
				count++;
			}
			writer.println();

			// Write function pointer typedefs
			writer.println("/* ==================== Function Definitions ==================== */");
			writer.println();
			for (DataType dt : funcDefs) {
				FunctionDefinition fd = (FunctionDefinition) dt;
				writer.println("/* " + fd.getPrototypeString() + " */");
				count++;
			}
			writer.println();

			writer.println("/* Total types exported: " + count + " */");
		}
		return count;
	}

	// -----------------------------------------------------------------------
	// Summary
	// -----------------------------------------------------------------------

	private void writeSummary(File outputFile, Program program, int exported, int failed,
			int stringCount, int importCount, int typeCount) throws IOException {
		try (PrintWriter writer = new PrintWriter(new FileOutputStream(outputFile))) {
			writer.println("=== Export Summary ===");
			writer.println();
			writer.println("Binary: " + program.getName());
			writer.println("Format: " + program.getExecutableFormat());
			writer.println("Language: " + program.getLanguage().getLanguageDescription()
				.getDescription());
			writer.println("Compiler: " + program.getCompilerSpec().getCompilerSpecID());
			writer.println("Image Base: " + program.getImageBase());
			writer.println();
			writer.println("--- Exported ---");
			writer.println("Functions exported:   " + exported);
			writer.println("Functions failed:     " + failed);
			writer.println("Strings extracted:    " + stringCount);
			writer.println("Imports listed:       " + importCount);
			writer.println("Types exported:       " + typeCount);
			writer.println();
			writer.println("--- Function Statistics ---");
			FunctionManager funcMgr = program.getFunctionManager();
			int totalFuncs = funcMgr.getFunctionCount();
			int namedCount = 0;
			int autoCount = 0;
			int thunkCount = 0;
			FunctionIterator iter = funcMgr.getFunctions(true);
			while (iter.hasNext()) {
				Function f = iter.next();
				if (f.isThunk()) {
					thunkCount++;
				}
				else if (f.getName().startsWith("FUN_")) {
					autoCount++;
				}
				else {
					namedCount++;
				}
			}
			writer.println("Total functions:      " + totalFuncs);
			writer.println("Named (user):         " + namedCount);
			writer.println("Auto-generated:       " + autoCount);
			writer.println("Thunks:               " + thunkCount);
			writer.println();

			// Memory sections
			writer.println("--- Memory Sections ---");
			for (ghidra.program.model.mem.MemoryBlock block :
				program.getMemory().getBlocks()) {
				String perms = "";
				perms += block.isRead() ? "r" : "-";
				perms += block.isWrite() ? "w" : "-";
				perms += block.isExecute() ? "x" : "-";
				writer.printf("  %-20s %s  size: 0x%x  [%s]%n",
					block.getName(), block.getStart(), block.getSize(), perms);
			}
			writer.println();

			writer.println("--- Directory Structure ---");
			writer.println("  functions/            - All functions (flat listing)");
			writer.println("  by_namespace/         - Functions grouped by namespace/class");
			writer.println("  by_category/          - Functions by type (user/auto/stubs/entry)");
			writer.println("  imports/              - External library imports");
			writer.println("  strings/              - Defined string constants");
			writer.println("  types/                - Data types as C header");
		}
	}

	// -----------------------------------------------------------------------
	// Utilities
	// -----------------------------------------------------------------------

	private static void writeFile(File file, String content) throws IOException {
		try (PrintWriter writer = new PrintWriter(new FileOutputStream(file))) {
			writer.write(content);
		}
	}

	/**
	 * Sanitize a string for use as a filename.
	 */
	private static String sanitizeFilename(String name) {
		if (name == null || name.isEmpty()) {
			return "unnamed";
		}
		// Replace characters not safe for filenames
		String safe = name.replaceAll("[^a-zA-Z0-9._\\-]", "_");
		// Collapse multiple underscores
		safe = safe.replaceAll("_+", "_");
		// Trim leading/trailing underscores
		safe = safe.replaceAll("^_+|_+$", "");
		if (safe.isEmpty()) {
			safe = "unnamed";
		}
		// Limit length
		if (safe.length() > 200) {
			safe = safe.substring(0, 200);
		}
		return safe;
	}

	/**
	 * Sanitize a name for use as a C identifier.
	 */
	private static String sanitizeCName(String name) {
		if (name == null || name.isEmpty()) {
			return "unnamed";
		}
		String safe = name.replaceAll("[^a-zA-Z0-9_]", "_");
		if (safe.length() > 0 && Character.isDigit(safe.charAt(0))) {
			safe = "_" + safe;
		}
		return safe;
	}
}
