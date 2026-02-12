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

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.io.*;
import java.util.*;

import javax.swing.*;

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
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Action to export decompiled C code with flexible options:
 *   - Entire binary as a single .c file
 *   - By namespace (one .c file per namespace)
 *   - Current function only
 *
 * Accessed via: File > Export C Code...
 */
public class ExportCCodeAction extends AbstractDecompilerAction {

	private static final String LAST_USED_EXPORT_DIR = "last.used.ccode.export.dir";

	// Export mode constants
	private static final int MODE_SINGLE_FILE = 0;
	private static final int MODE_BY_NAMESPACE = 1;
	private static final int MODE_CURRENT_FUNCTION = 2;

	public ExportCCodeAction() {
		super("Export C Code");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ToolBarExport"));
		setMenuBarData(
			new MenuData(new String[] { "Export C Code..." }, "xExport"));
		setDescription("Export decompiled C code (single file, by namespace, or current function)");
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return context.getProgram() != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();

		// Build export options dialog with filter checkboxes
		JPanel dialogPanel = new JPanel();
		dialogPanel.setLayout(new BoxLayout(dialogPanel, BoxLayout.Y_AXIS));
		dialogPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JLabel modeLabel = new JLabel("Export Mode:");
		modeLabel.setFont(modeLabel.getFont().deriveFont(Font.BOLD));
		modeLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
		dialogPanel.add(modeLabel);
		dialogPanel.add(Box.createVerticalStrut(5));

		JRadioButton rbSingleFile = new JRadioButton("Entire Binary (single .c file)", true);
		JRadioButton rbByNamespace = new JRadioButton("By Namespace (one file per namespace)");
		JRadioButton rbCurrentFunc = new JRadioButton("Current Function Only");
		ButtonGroup modeGroup = new ButtonGroup();
		modeGroup.add(rbSingleFile);
		modeGroup.add(rbByNamespace);
		modeGroup.add(rbCurrentFunc);

		rbSingleFile.setAlignmentX(Component.LEFT_ALIGNMENT);
		rbByNamespace.setAlignmentX(Component.LEFT_ALIGNMENT);
		rbCurrentFunc.setAlignmentX(Component.LEFT_ALIGNMENT);
		dialogPanel.add(rbSingleFile);
		dialogPanel.add(rbByNamespace);
		dialogPanel.add(rbCurrentFunc);

		dialogPanel.add(Box.createVerticalStrut(15));
		JSeparator sep = new JSeparator();
		sep.setAlignmentX(Component.LEFT_ALIGNMENT);
		sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 2));
		dialogPanel.add(sep);
		dialogPanel.add(Box.createVerticalStrut(10));

		JLabel filterLabel = new JLabel("Filter Options:");
		filterLabel.setFont(filterLabel.getFont().deriveFont(Font.BOLD));
		filterLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
		dialogPanel.add(filterLabel);
		dialogPanel.add(Box.createVerticalStrut(5));

		JCheckBox cbSkipUndefined = new JCheckBox(
			"Skip undefined/auto-named stubs (FUN_*, thunk_FUN_*)", true);
		cbSkipUndefined.setAlignmentX(Component.LEFT_ALIGNMENT);
		dialogPanel.add(cbSkipUndefined);

		JCheckBox cbSkipThunks = new JCheckBox(
			"Skip thunks and external stubs", true);
		cbSkipThunks.setAlignmentX(Component.LEFT_ALIGNMENT);
		dialogPanel.add(cbSkipThunks);

		JCheckBox cbSkipEmpty = new JCheckBox(
			"Skip functions with empty/failed decompilation", true);
		cbSkipEmpty.setAlignmentX(Component.LEFT_ALIGNMENT);
		dialogPanel.add(cbSkipEmpty);

		dialogPanel.add(Box.createVerticalStrut(10));

		// Count functions to give the user an idea
		FunctionManager funcMgr = program.getFunctionManager();
		int totalFuncs = funcMgr.getFunctionCount();
		int autoFuncs = 0;
		int thunkFuncs = 0;
		FunctionIterator iter = funcMgr.getFunctions(true);
		while (iter.hasNext()) {
			Function f = iter.next();
			if (f.getName().startsWith("FUN_") || f.getName().startsWith("thunk_FUN_")) {
				autoFuncs++;
			}
			if (f.isThunk() || f.isExternal()) {
				thunkFuncs++;
			}
		}

		JLabel statsLabel = new JLabel(String.format(
			"<html><i>Binary has %d functions: %d named, %d auto-generated (FUN_*), %d thunks/external</i></html>",
			totalFuncs, totalFuncs - autoFuncs - thunkFuncs, autoFuncs, thunkFuncs));
		statsLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
		statsLabel.setForeground(Color.GRAY);
		dialogPanel.add(statsLabel);

		int result = JOptionPane.showConfirmDialog(
			context.getDecompilerPanel(),
			dialogPanel,
			"Export C Code - Binhunters",
			JOptionPane.OK_CANCEL_OPTION,
			JOptionPane.PLAIN_MESSAGE);

		if (result != JOptionPane.OK_OPTION) {
			return;
		}

		// Build filter settings
		ExportFilter filter = new ExportFilter(
			cbSkipUndefined.isSelected(),
			cbSkipThunks.isSelected(),
			cbSkipEmpty.isSelected());

		if (rbCurrentFunc.isSelected()) {
			exportCurrentFunction(context);
		}
		else if (rbSingleFile.isSelected()) {
			File file = chooseOutputFile(context, program.getName() + "_full.c");
			if (file != null) {
				ExportSingleFileTask task =
					new ExportSingleFileTask(program, file, context, filter);
				context.getTool().execute(task, 500);
			}
		}
		else if (rbByNamespace.isSelected()) {
			File dir = chooseOutputDirectory(context);
			if (dir != null) {
				ExportByNamespaceTask task =
					new ExportByNamespaceTask(program, dir, context, filter);
				context.getTool().execute(task, 500);
			}
		}
	}

	/**
	 * Filter settings for export.
	 */
	private static class ExportFilter {
		final boolean skipUndefined;
		final boolean skipThunks;
		final boolean skipEmpty;

		ExportFilter(boolean skipUndefined, boolean skipThunks, boolean skipEmpty) {
			this.skipUndefined = skipUndefined;
			this.skipThunks = skipThunks;
			this.skipEmpty = skipEmpty;
		}

		boolean shouldInclude(FuncResult result) {
			if (result == null) {
				return false;
			}
			if (skipEmpty && (result.cCode == null || result.cCode.isEmpty())) {
				return false;
			}
			if (skipUndefined && (result.name.startsWith("FUN_") ||
				result.name.startsWith("thunk_FUN_"))) {
				return false;
			}
			if (skipThunks && result.isThunk) {
				return false;
			}
			return true;
		}
	}

	private File chooseOutputFile(DecompilerActionContext context, String defaultName) {
		String lastDir = Preferences.getProperty(LAST_USED_EXPORT_DIR);
		GhidraFileChooser chooser = new GhidraFileChooser(context.getDecompilerPanel());
		chooser.setTitle("Save C Code File");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setApproveButtonText("Save");
		if (lastDir != null) {
			chooser.setSelectedFile(new File(lastDir, defaultName));
		}
		else {
			chooser.setSelectedFile(new File(defaultName));
		}
		File file = chooser.getSelectedFile();
		chooser.dispose();
		if (file != null) {
			Preferences.setProperty(LAST_USED_EXPORT_DIR, file.getParent());
			Preferences.store();
			// Ensure .c extension
			if (!file.getName().endsWith(".c") && !file.getName().endsWith(".h")) {
				file = new File(file.getAbsolutePath() + ".c");
			}
		}
		return file;
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

	// -----------------------------------------------------------------------
	// Export current function (quick export)
	// -----------------------------------------------------------------------

	private void exportCurrentFunction(DecompilerActionContext context) {
		ClangTokenGroup grp = context.getCCodeModel();
		if (grp == null) {
			Msg.showInfo(this, context.getDecompilerPanel(), "No Decompilation",
				"No decompiled function is currently displayed.");
			return;
		}

		Function func = context.getFunction();
		String defaultName = (func != null) ? sanitizeFilename(func.getName()) + ".c" : "function.c";

		File file = chooseOutputFile(context, defaultName);
		if (file == null) {
			return;
		}

		try (PrintWriter writer = new PrintWriter(new FileOutputStream(file))) {
			Program program = context.getProgram();
			writer.println("/*");
			writer.println(" * Decompiled by Binhunters");
			writer.println(" * Binary: " + program.getName());
			writer.println(" * Language: " + program.getLanguage().getLanguageDescription()
				.getDescription());
			if (func != null) {
				writer.println(" * Function: " + func.getName() +
					" @ " + func.getEntryPoint());
			}
			writer.println(" */");
			writer.println();

			// Write the decompiled C
			PrettyPrinter pp = new PrettyPrinter(func, grp, null);
			DecompiledFunction df = pp.print();
			writer.print(df.getC());

			Msg.info(this, "Exported function to: " + file.getAbsolutePath());
		}
		catch (Exception e) {
			Msg.error(this, "Export failed", e);
		}
	}

	// -----------------------------------------------------------------------
	// Export entire binary to single .c file
	// -----------------------------------------------------------------------

	private class ExportSingleFileTask extends Task {
		private final Program program;
		private final File outputFile;
		private final DecompilerActionContext context;
		private final ExportFilter filter;

		ExportSingleFileTask(Program program, File outputFile,
				DecompilerActionContext context, ExportFilter filter) {
			super("Exporting C Code (Single File)", true, true, true);
			this.program = program;
			this.outputFile = outputFile;
			this.context = context;
			this.filter = filter;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			try {
				doExport(monitor);
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				Msg.error(ExportCCodeAction.class, "Export failed", e);
			}
		}

		private void doExport(TaskMonitor monitor) throws Exception {
			FunctionManager funcMgr = program.getFunctionManager();
			int totalFunctions = funcMgr.getFunctionCount();
			monitor.initialize(totalFunctions + 2);

			// Step 1: Decompile all functions
			monitor.setMessage("Decompiling all functions...");
			List<FuncResult> results = decompileAll(program, monitor);

			if (monitor.isCancelled()) {
				return;
			}

			// Sort by address for clean output
			results.sort((a, b) -> a.address.compareTo(b.address));

			// Apply filter
			List<FuncResult> filtered = new ArrayList<>();
			List<FuncResult> skipped = new ArrayList<>();
			for (FuncResult r : results) {
				if (filter.shouldInclude(r)) {
					filtered.add(r);
				}
				else if (r != null) {
					skipped.add(r);
				}
			}

			// Step 2: Write the single file
			monitor.setMessage("Writing C code...");
			try (PrintWriter writer = new PrintWriter(new FileOutputStream(outputFile))) {
				// File header
				writer.println("/*");
				writer.println(
					" * ============================================================================");
				writer.println(
					" * Decompiled by Binhunters");
				writer.println(
					" * Binary: " + program.getName());
				writer.println(
					" * Format: " + program.getExecutableFormat());
				writer.println(
					" * Language: " + detectLanguage(program));
				writer.println(
					" * Architecture: " + program.getLanguage().getLanguageDescription()
						.getDescription());
				writer.println(
					" * Compiler: " + program.getCompilerSpec().getCompilerSpecID());
				writer.println(
					" * Image Base: " + program.getImageBase());
				writer.println(
					" * Total Functions: " + totalFunctions);
				writer.println(
					" * Exported: " + filtered.size() +
					" (skipped " + skipped.size() + " stubs/thunks)");
				writer.println(
					" * ============================================================================");
				writer.println(" */");
				writer.println();

				// Include standard headers
				writer.println("#include <stdint.h>");
				writer.println("#include <stdbool.h>");
				writer.println("#include <stddef.h>");
				writer.println();

				// Type definitions
				monitor.setMessage("Exporting type definitions...");
				writeTypeDefinitions(writer, program);
				monitor.incrementProgress(1);

				if (monitor.isCancelled()) {
					return;
				}

				// Forward declarations (prototypes) — only for included functions
				writer.println();
				writer.println("/* ========== Forward Declarations ========== */");
				writer.println();
				for (FuncResult result : filtered) {
					if (result.cCode != null && result.prototype != null) {
						writer.println(result.prototype + ";");
					}
				}

				// If there are skipped functions, add a comment noting them
				if (!skipped.isEmpty()) {
					writer.println();
					writer.println("/* " + skipped.size() +
						" auto-generated/stub functions were excluded from this export.");
					writer.println(
						" * To include them, uncheck the filter options in the export dialog. */");
				}
				writer.println();
				monitor.incrementProgress(1);

				// Function implementations
				writer.println("/* ========== Function Implementations ========== */");
				writer.println();

				int exported = 0;
				for (FuncResult result : filtered) {
					if (monitor.isCancelled()) {
						return;
					}

					if (result.cCode == null || result.cCode.isEmpty()) {
						continue;
					}

					writer.println();
					writer.println(
						"/* ---------------------------------------------------------------");
					writer.printf(
						" * %s @ %s", result.name, result.address);
					writer.println();
					if (result.namespace != null && !result.namespace.isEmpty()) {
						writer.printf(" * Namespace: %s", result.namespace);
						writer.println();
					}
					writer.println(
						" * --------------------------------------------------------------- */");
					writer.println();
					writer.println(result.cCode);
					exported++;
					monitor.incrementProgress(1);
				}

				writer.println();
				writer.println("/* End of decompiled code */");
				writer.printf("/* Exported: %d functions (skipped %d stubs/thunks out of %d total) */",
					exported, skipped.size(), totalFunctions);
				writer.println();
			}

			Msg.info(ExportCCodeAction.class,
				"Exported " + filtered.size() + " functions to: " + outputFile.getAbsolutePath() +
				" (skipped " + skipped.size() + " stubs/thunks)");
		}
	}

	// -----------------------------------------------------------------------
	// Export by namespace
	// -----------------------------------------------------------------------

	private class ExportByNamespaceTask extends Task {
		private final Program program;
		private final File outputDir;
		private final DecompilerActionContext context;
		private final ExportFilter filter;

		ExportByNamespaceTask(Program program, File outputDir,
				DecompilerActionContext context, ExportFilter filter) {
			super("Exporting C Code (By Namespace)", true, true, true);
			this.program = program;
			this.outputDir = outputDir;
			this.context = context;
			this.filter = filter;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			try {
				doExport(monitor);
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				Msg.error(ExportCCodeAction.class, "Export failed", e);
			}
		}

		private void doExport(TaskMonitor monitor) throws Exception {
			FunctionManager funcMgr = program.getFunctionManager();
			int totalFunctions = funcMgr.getFunctionCount();
			monitor.initialize(totalFunctions + 1);

			// Step 1: Decompile all
			monitor.setMessage("Decompiling all functions...");
			List<FuncResult> results = decompileAll(program, monitor);

			if (monitor.isCancelled()) {
				return;
			}

			// Step 2: Group by namespace (applying filter)
			Map<String, List<FuncResult>> byNamespace = new LinkedHashMap<>();
			int skippedCount = 0;
			for (FuncResult result : results) {
				if (!filter.shouldInclude(result)) {
					skippedCount++;
					continue;
				}
				String ns = result.namespace;
				if (ns == null || ns.isEmpty() || ns.equals("Global") ||
					ns.equals(program.getName())) {
					ns = "_global";
				}
				byNamespace.computeIfAbsent(ns, k -> new ArrayList<>()).add(result);
			}

			// Step 3: Write a shared types header
			File typesFile = new File(outputDir, "types.h");
			outputDir.mkdirs();
			try (PrintWriter writer = new PrintWriter(new FileOutputStream(typesFile))) {
				writer.println("/* Type definitions for " + program.getName() + " */");
				writer.println("#pragma once");
				writer.println();
				writer.println("#include <stdint.h>");
				writer.println("#include <stdbool.h>");
				writer.println("#include <stddef.h>");
				writer.println();
				writeTypeDefinitions(writer, program);
			}
			monitor.incrementProgress(1);

			// Step 4: Write one .c file per namespace
			monitor.setMessage("Writing namespace files...");
			for (Map.Entry<String, List<FuncResult>> entry : byNamespace.entrySet()) {
				if (monitor.isCancelled()) {
					return;
				}

				String nsName = sanitizeFilename(entry.getKey());
				List<FuncResult> funcs = entry.getValue();
				funcs.sort((a, b) -> a.address.compareTo(b.address));

				File nsFile = new File(outputDir, nsName + ".c");
				try (PrintWriter writer = new PrintWriter(new FileOutputStream(nsFile))) {
					writer.println("/*");
					writer.println(" * Namespace: " + entry.getKey());
					writer.println(" * Binary: " + program.getName());
					writer.println(" * Functions: " + funcs.size());
					writer.println(" * Decompiled by Binhunters");
					writer.println(" */");
					writer.println();
					writer.println("#include \"types.h\"");
					writer.println();

					// Forward declarations
					for (FuncResult func : funcs) {
						if (func.prototype != null) {
							writer.println(func.prototype + ";");
						}
					}
					writer.println();

					// Implementations
					for (FuncResult func : funcs) {
						if (func.cCode == null || func.cCode.isEmpty()) {
							continue;
						}
						writer.println(
							"/* " + func.name + " @ " + func.address + " */");
						writer.println(func.cCode);
						writer.println();
					}
				}
			}

			Msg.info(ExportCCodeAction.class,
				"Exported " + byNamespace.size() + " namespace files to: " +
					outputDir.getAbsolutePath());
		}
	}

	// -----------------------------------------------------------------------
	// Shared decompilation
	// -----------------------------------------------------------------------

	private static List<FuncResult> decompileAll(Program program, TaskMonitor monitor)
			throws Exception {

		DecompileConfigurer configurer = decompiler -> {
			DecompileOptions options = new DecompileOptions();
			decompiler.setOptions(options);
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(false);
		};

		DecompilerCallback<FuncResult> callback =
			new DecompilerCallback<FuncResult>(program, configurer) {
				@Override
				public FuncResult process(DecompileResults results, TaskMonitor mon)
						throws Exception {
					Function func = results.getFunction();
					if (func == null) {
						return null;
					}

					String cCode = null;
					String prototype = null;
					if (results.decompileCompleted()) {
						DecompiledFunction df = results.getDecompiledFunction();
						if (df != null) {
							cCode = df.getC();
						}
					}

					// Build prototype
					prototype = func.getPrototypeString(true, false);

					Namespace ns = func.getParentNamespace();
					String namespace = (ns != null && !ns.isGlobal()) ? ns.getName(true) : "";
					boolean isThunk = func.isThunk() || func.isExternal();

					return new FuncResult(func.getName(),
						func.getEntryPoint().toString().replace(":", "_"),
						namespace, cCode, prototype, isThunk);
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
	// Type definitions writer
	// -----------------------------------------------------------------------

	private static void writeTypeDefinitions(PrintWriter writer, Program program) {
		DataTypeManager dtm = program.getDataTypeManager();

		List<DataType> enums = new ArrayList<>();
		List<DataType> structs = new ArrayList<>();
		List<DataType> typedefs = new ArrayList<>();

		Iterator<DataType> allTypes = dtm.getAllDataTypes();
		while (allTypes.hasNext()) {
			DataType dt = allTypes.next();
			if (dt.getDataTypeManager() != dtm) {
				continue;
			}
			if (dt instanceof ghidra.program.model.data.Enum) {
				enums.add(dt);
			}
			else if (dt instanceof Structure) {
				structs.add(dt);
			}
			else if (dt instanceof TypeDef) {
				typedefs.add(dt);
			}
		}

		if (!enums.isEmpty()) {
			writer.println("/* ========== Enumerations ========== */");
			writer.println();
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
			}
		}

		if (!structs.isEmpty()) {
			writer.println("/* ========== Forward Declarations ========== */");
			writer.println();
			for (DataType dt : structs) {
				writer.println("typedef struct " + sanitizeCName(dt.getName()) + " " +
					sanitizeCName(dt.getName()) + ";");
			}
			writer.println();

			writer.println("/* ========== Structure Definitions ========== */");
			writer.println();
			for (DataType dt : structs) {
				Structure s = (Structure) dt;
				writer.println("struct " + sanitizeCName(s.getName()) + " {");
				for (DataTypeComponent comp : s.getDefinedComponents()) {
					String fieldName = (comp.getFieldName() != null)
						? comp.getFieldName()
						: "field_" + Integer.toHexString(comp.getOffset());
					writer.println("    " + comp.getDataType().getDisplayName() + " " +
						fieldName + ";  /* offset: 0x" +
						Integer.toHexString(comp.getOffset()) + " */");
				}
				writer.println("};  /* sizeof = " + s.getLength() + " */");
				writer.println();
			}
		}

		if (!typedefs.isEmpty()) {
			writer.println("/* ========== Typedefs ========== */");
			writer.println();
			for (DataType dt : typedefs) {
				TypeDef td = (TypeDef) dt;
				writer.println("typedef " + td.getBaseDataType().getDisplayName() + " " +
					sanitizeCName(td.getName()) + ";");
			}
			writer.println();
		}
	}

	// -----------------------------------------------------------------------
	// Language detection
	// -----------------------------------------------------------------------

	/**
	 * Detect the likely source language of the binary based on imports,
	 * symbols, and section characteristics.
	 */
	static String detectLanguage(Program program) {
		SymbolTable symTab = program.getSymbolTable();
		String format = program.getExecutableFormat();
		String compiler = program.getCompilerSpec().getCompilerSpecID().toString();
		Listing listing = program.getListing();

		int objcCount = 0;
		int cppCount = 0;
		int swiftCount = 0;
		int rustCount = 0;
		int goCount = 0;
		int javaCount = 0;
		int cCount = 0;

		// Scan symbols for language indicators
		SymbolIterator symbols = symTab.getAllSymbols(true);
		int scanned = 0;
		while (symbols.hasNext() && scanned < 5000) {
			Symbol sym = symbols.next();
			String name = sym.getName();
			scanned++;

			// Objective-C indicators
			if (name.startsWith("_objc_") || name.startsWith("objc_msg") ||
				name.contains("@") && name.contains(":") ||
				name.startsWith("+[") || name.startsWith("-[") ||
				name.startsWith("_OBJC_")) {
				objcCount++;
			}
			// C++ indicators (mangled names)
			else if (name.startsWith("_Z") || name.startsWith("__Z") ||
				name.contains("::") || name.startsWith("std__") ||
				name.contains("__cxa_") || name.contains("vtable")) {
				cppCount++;
			}
			// Swift indicators
			else if (name.startsWith("_$s") || name.startsWith("$s") ||
				name.contains("Swift") || name.startsWith("_swift_")) {
				swiftCount++;
			}
			// Rust indicators
			else if (name.contains("$LT$") || name.contains("$GT$") ||
				name.contains("core..") || name.contains("alloc..") ||
				name.contains("__rust_") || name.startsWith("_ZN")) {
				if (name.contains("$LT$") || name.contains("__rust_") ||
					name.contains("core..")) {
					rustCount++;
				}
				else {
					cppCount++; // _ZN is shared with C++
				}
			}
			// Go indicators
			else if (name.startsWith("go.") || name.startsWith("runtime.") ||
				name.contains("go_") || name.startsWith("main.main")) {
				goCount++;
			}
		}

		// Check memory sections for additional clues
		for (ghidra.program.model.mem.MemoryBlock block : program.getMemory().getBlocks()) {
			String blockName = block.getName().toLowerCase();
			if (blockName.contains("objc") || blockName.equals("__cfstring")) {
				objcCount += 5;
			}
			if (blockName.contains("swift")) {
				swiftCount += 5;
			}
			if (blockName.contains("gopclntab") || blockName.equals(".gosymtab")) {
				goCount += 10;
			}
		}

		// Check format-specific patterns
		if (format != null) {
			String fmtLower = format.toLowerCase();
			if (fmtLower.contains("dex") || fmtLower.contains("dalvik")) {
				return "Java/Kotlin (Android DEX)";
			}
			if (fmtLower.contains("class")) {
				return "Java (JVM Bytecode)";
			}
			if (fmtLower.contains(".net") || fmtLower.contains("cli")) {
				return "C#/.NET";
			}
		}

		// Determine dominant language
		Map<String, Integer> scores = new LinkedHashMap<>();
		scores.put("Objective-C", objcCount);
		scores.put("C++", cppCount);
		scores.put("Swift", swiftCount);
		scores.put("Rust", rustCount);
		scores.put("Go", goCount);

		String bestLang = "C";
		int bestScore = 0;
		for (Map.Entry<String, Integer> entry : scores.entrySet()) {
			if (entry.getValue() > bestScore) {
				bestScore = entry.getValue();
				bestLang = entry.getKey();
			}
		}

		// Require minimum confidence
		if (bestScore < 3) {
			bestLang = "C";
		}

		// Build result with confidence
		StringBuilder result = new StringBuilder(bestLang);
		if (bestScore >= 20) {
			result.append(" (high confidence)");
		}
		else if (bestScore >= 5) {
			result.append(" (medium confidence)");
		}
		else if (bestScore >= 3) {
			result.append(" (low confidence)");
		}

		return result.toString();
	}

	// -----------------------------------------------------------------------
	// Utilities
	// -----------------------------------------------------------------------

	private static class FuncResult {
		final String name;
		final String address;
		final String namespace;
		final String cCode;
		final String prototype;
		final boolean isThunk;

		FuncResult(String name, String address, String namespace,
				String cCode, String prototype, boolean isThunk) {
			this.name = name;
			this.address = address;
			this.namespace = namespace;
			this.cCode = cCode;
			this.prototype = prototype;
			this.isThunk = isThunk;
		}
	}

	private static String sanitizeFilename(String name) {
		if (name == null || name.isEmpty()) {
			return "unnamed";
		}
		String safe = name.replaceAll("[^a-zA-Z0-9._\\-]", "_");
		safe = safe.replaceAll("_+", "_").replaceAll("^_+|_+$", "");
		if (safe.isEmpty()) {
			safe = "unnamed";
		}
		if (safe.length() > 200) {
			safe = safe.substring(0, 200);
		}
		return safe;
	}

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
