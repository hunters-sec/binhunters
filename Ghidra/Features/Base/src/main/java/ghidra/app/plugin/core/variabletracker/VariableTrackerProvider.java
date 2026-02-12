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
package ghidra.app.plugin.core.variabletracker;

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Provider for the Variable Tracker panel. Analyzes the binary to find:
 *
 * 1. Global variables (data symbols) used by multiple functions
 * 2. Cross-references showing which functions read/write each variable
 * 3. Function parameters and their call-site connections
 * 4. Shared data dependencies between functions
 *
 * The panel has three views:
 *   - Global Variables: shows all globals sorted by usage count
 *   - Current Function: shows variables in the selected function and where they're used
 *   - Shared Data: shows variables that connect multiple functions
 */
public class VariableTrackerProvider extends ComponentProviderAdapter {

	private static final String TITLE = "Variable Tracker";
	private static final int MAX_REFS_PER_VARIABLE = 100;

	private VariableTrackerPlugin plugin;
	private Program program;
	private JPanel mainPanel;
	private JTabbedPane tabbedPane;

	// Global Variables tab
	private JPanel globalsPanel;
	private JTable globalsTable;
	private GlobalsTableModel globalsModel;
	private JLabel globalsStatusLabel;

	// Current Function tab
	private JPanel functionPanel;
	private JPanel functionContentPanel;

	// Shared Data tab
	private JPanel sharedPanel;
	private JTable sharedTable;
	private SharedDataTableModel sharedModel;
	private JLabel sharedStatusLabel;

	// State
	private Address lastAddress;
	private boolean analysisRunning = false;

	VariableTrackerProvider(VariableTrackerPlugin plugin) {
		super(plugin.getTool(), TITLE, plugin.getName());
		this.plugin = plugin;

		setTitle(TITLE);
		setHelpLocation(new HelpLocation(plugin.getName(), plugin.getName()));

		mainPanel = new JPanel(new BorderLayout());
		tabbedPane = new JTabbedPane();

		buildGlobalsTab();
		buildFunctionTab();
		buildSharedDataTab();

		tabbedPane.addTab("Global Variables", globalsPanel);
		tabbedPane.addTab("Current Function", functionPanel);
		tabbedPane.addTab("Shared Data", sharedPanel);

		mainPanel.add(tabbedPane, BorderLayout.CENTER);

		// Add menu actions
		createActions();

		addToTool();
	}

	private void createActions() {
		new ActionBuilder("Analyze Variables", plugin.getName())
			.menuPath("&Analysis", "Variable Tracker", "Analyze Global Variables")
			.menuGroup("VariableTracker")
			.description("Scan all global variables and compute cross-function usage")
			.onAction(ctx -> analyzeGlobals())
			.buildAndInstall(dockingTool);

		new ActionBuilder("Refresh Variable Tracker", plugin.getName())
			.menuPath("&Analysis", "Variable Tracker", "Refresh")
			.menuGroup("VariableTracker")
			.description("Refresh the variable tracker analysis")
			.onAction(ctx -> {
				analyzeGlobals();
				analyzeSharedData();
			})
			.buildAndInstall(dockingTool);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	void setProgram(Program newProgram) {
		this.program = newProgram;
		this.lastAddress = null;

		if (program == null) {
			globalsModel.clear();
			sharedModel.clear();
			clearFunctionPanel("No program loaded");
		}
		else {
			clearFunctionPanel("Navigate to a function to see variable usage");
			// Auto-analyze on program load
			analyzeGlobals();
			analyzeSharedData();
		}
	}

	void locationChanged(ProgramLocation loc) {
		if (program == null || loc == null) {
			return;
		}

		Address addr = loc.getAddress();
		if (addr == null) {
			return;
		}

		// Only rebuild function tab if we moved to a different function
		Function func = program.getFunctionManager().getFunctionContaining(addr);
		if (func != null) {
			Address entry = func.getEntryPoint();
			if (!entry.equals(lastAddress)) {
				lastAddress = entry;
				buildFunctionVariables(func);
			}
		}
	}

	// =======================================================================
	// GLOBALS TAB
	// =======================================================================

	private void buildGlobalsTab() {
		globalsPanel = new JPanel(new BorderLayout());
		globalsPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

		// Header with description and button
		JPanel headerPanel = new JPanel(new BorderLayout());
		JLabel descLabel = new JLabel(
			"<html>Global variables sorted by usage count. " +
			"Variables used by many functions are likely important shared state.</html>");
		descLabel.setBorder(new EmptyBorder(4, 4, 8, 4));
		headerPanel.add(descLabel, BorderLayout.CENTER);

		JButton analyzeBtn = new JButton("Analyze");
		analyzeBtn.addActionListener(e -> analyzeGlobals());
		JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		btnPanel.add(analyzeBtn);
		headerPanel.add(btnPanel, BorderLayout.EAST);

		globalsPanel.add(headerPanel, BorderLayout.NORTH);

		// Table
		globalsModel = new GlobalsTableModel();
		globalsTable = new JTable(globalsModel);
		globalsTable.setRowHeight(22);
		globalsTable.setAutoCreateRowSorter(true);
		globalsTable.setFillsViewportHeight(true);

		// Column widths
		globalsTable.getColumnModel().getColumn(0).setPreferredWidth(180); // Name
		globalsTable.getColumnModel().getColumn(1).setPreferredWidth(120); // Address
		globalsTable.getColumnModel().getColumn(2).setPreferredWidth(120); // Type
		globalsTable.getColumnModel().getColumn(3).setPreferredWidth(60);  // Usage Count
		globalsTable.getColumnModel().getColumn(4).setPreferredWidth(300); // Used By Functions

		// Color the usage count column
		globalsTable.getColumnModel().getColumn(3).setCellRenderer(new UsageCountRenderer());

		JScrollPane scrollPane = new JScrollPane(globalsTable);
		globalsPanel.add(scrollPane, BorderLayout.CENTER);

		// Status bar
		globalsStatusLabel = new JLabel(" ");
		globalsStatusLabel.setBorder(new EmptyBorder(4, 4, 4, 4));
		globalsPanel.add(globalsStatusLabel, BorderLayout.SOUTH);
	}

	private void analyzeGlobals() {
		if (program == null || analysisRunning) {
			return;
		}
		analysisRunning = true;
		globalsStatusLabel.setText("Analyzing global variables...");

		// Run in background thread
		new Thread(() -> {
			try {
				List<GlobalVarEntry> entries = scanGlobalVariables();
				SwingUtilities.invokeLater(() -> {
					globalsModel.setEntries(entries);
					globalsStatusLabel.setText(String.format(
						"Found %d global variables referenced by functions", entries.size()));
					analysisRunning = false;
				});
			}
			catch (Exception e) {
				Msg.error(this, "Error analyzing globals", e);
				SwingUtilities.invokeLater(() -> {
					globalsStatusLabel.setText("Error: " + e.getMessage());
					analysisRunning = false;
				});
			}
		}, "VariableTracker-GlobalAnalysis").start();
	}

	/**
	 * Scan all defined data in the program and find which functions reference each one.
	 */
	private List<GlobalVarEntry> scanGlobalVariables() {
		List<GlobalVarEntry> results = new ArrayList<>();
		if (program == null) {
			return results;
		}

		ReferenceManager refMgr = program.getReferenceManager();
		FunctionManager funcMgr = program.getFunctionManager();
		Listing listing = program.getListing();
		SymbolTable symTab = program.getSymbolTable();

		// Find all labeled data addresses (global variables)
		Map<Address, GlobalVarEntry> entryMap = new LinkedHashMap<>();

		// Approach 1: Scan symbols that are labels or data in non-code sections
		SymbolIterator symbols = symTab.getAllSymbols(true);
		while (symbols.hasNext()) {
			Symbol sym = symbols.next();
			if (sym.isExternal() || sym.isDynamic()) {
				continue;
			}

			SymbolType type = sym.getSymbolType();
			Address addr = sym.getAddress();

			// We want data labels (global variables), not function names
			if (type == SymbolType.LABEL || type == SymbolType.GLOBAL_VAR) {
				// Skip addresses inside functions (code labels)
				if (funcMgr.getFunctionAt(addr) != null) {
					continue;
				}

				// Check if this address has data defined
				Data data = listing.getDefinedDataAt(addr);
				String typeName = "(undefined)";
				if (data != null) {
					typeName = data.getDataType().getDisplayName();
				}

				// Find all functions that reference this address
				Set<String> usingFunctions = new LinkedHashSet<>();
				ReferenceIterator refs = refMgr.getReferencesTo(addr);
				int refCount = 0;
				while (refs.hasNext() && refCount < MAX_REFS_PER_VARIABLE) {
					Reference ref = refs.next();
					Function fromFunc = funcMgr.getFunctionContaining(ref.getFromAddress());
					if (fromFunc != null) {
						usingFunctions.add(fromFunc.getName());
					}
					refCount++;
				}

				if (!usingFunctions.isEmpty()) {
					GlobalVarEntry entry = new GlobalVarEntry(
						sym.getName(), addr, typeName,
						usingFunctions.size(), usingFunctions);
					entryMap.put(addr, entry);
				}
			}
		}

		// Approach 2: Also scan defined data items that may not have symbols
		DataIterator dataIter = listing.getDefinedData(true);
		while (dataIter.hasNext()) {
			Data data = dataIter.next();
			Address addr = data.getAddress();

			if (entryMap.containsKey(addr)) {
				continue; // Already processed via symbols
			}

			// Skip data inside functions
			if (funcMgr.getFunctionContaining(addr) != null) {
				continue;
			}

			// Skip very small/trivial data
			if (data.getLength() < 2) {
				continue;
			}

			Set<String> usingFunctions = new LinkedHashSet<>();
			ReferenceIterator refs = refMgr.getReferencesTo(addr);
			int refCount = 0;
			while (refs.hasNext() && refCount < MAX_REFS_PER_VARIABLE) {
				Reference ref = refs.next();
				Function fromFunc = funcMgr.getFunctionContaining(ref.getFromAddress());
				if (fromFunc != null) {
					usingFunctions.add(fromFunc.getName());
				}
				refCount++;
			}

			if (usingFunctions.size() >= 2) {
				// Only include unnamed data if used by multiple functions
				String name = "DAT_" + addr.toString();
				Symbol[] syms = symTab.getSymbols(addr);
				if (syms.length > 0) {
					name = syms[0].getName();
				}

				GlobalVarEntry entry = new GlobalVarEntry(
					name, addr, data.getDataType().getDisplayName(),
					usingFunctions.size(), usingFunctions);
				entryMap.put(addr, entry);
			}
		}

		results.addAll(entryMap.values());

		// Sort by usage count (most used first)
		results.sort((a, b) -> Integer.compare(b.usageCount, a.usageCount));

		return results;
	}

	// =======================================================================
	// FUNCTION TAB
	// =======================================================================

	private void buildFunctionTab() {
		functionPanel = new JPanel(new BorderLayout());
		functionPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

		functionContentPanel = new JPanel();
		functionContentPanel.setLayout(new BoxLayout(functionContentPanel, BoxLayout.Y_AXIS));

		JScrollPane scrollPane = new JScrollPane(functionContentPanel);
		scrollPane.getVerticalScrollBar().setUnitIncrement(16);
		functionPanel.add(scrollPane, BorderLayout.CENTER);

		clearFunctionPanel("No program loaded");
	}

	private void clearFunctionPanel(String message) {
		functionContentPanel.removeAll();
		JLabel emptyLabel = new JLabel(message, SwingConstants.CENTER);
		emptyLabel.setFont(emptyLabel.getFont().deriveFont(13f));
		emptyLabel.setForeground(Color.GRAY);
		emptyLabel.setBorder(new EmptyBorder(30, 15, 30, 15));
		functionContentPanel.add(emptyLabel);
		functionContentPanel.revalidate();
		functionContentPanel.repaint();
	}

	/**
	 * Build the function variables view for a specific function.
	 * Shows: parameters, local variables, globals accessed, strings referenced,
	 * and called functions with their shared variables.
	 */
	private void buildFunctionVariables(Function func) {
		functionContentPanel.removeAll();
		functionContentPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

		// Function header
		JPanel headerPanel = createSectionPanel("Function: " + func.getName());
		JLabel sigLabel = new JLabel("  " + func.getPrototypeString(true, false));
		sigLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
		sigLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
		headerPanel.add(sigLabel);
		addInfoRow(headerPanel, "Entry", func.getEntryPoint().toString());
		addInfoRow(headerPanel, "Size",
			String.format("0x%X bytes", func.getBody().getNumAddresses()));
		functionContentPanel.add(headerPanel);
		functionContentPanel.add(Box.createVerticalStrut(6));

		// Parameters section
		addParametersSection(func);

		// Local variables section
		addLocalVariablesSection(func);

		// Global data accessed by this function
		addGlobalAccessSection(func);

		// Strings referenced
		addStringsSection(func);

		// Data shared with other functions
		addSharedDataSection(func);

		functionContentPanel.add(Box.createVerticalGlue());
		functionContentPanel.revalidate();
		functionContentPanel.repaint();
	}

	private void addParametersSection(Function func) {
		Parameter[] params = func.getParameters();
		if (params.length == 0) {
			return;
		}

		JPanel panel = createSectionPanel("Parameters (" + params.length + ")");
		for (Parameter param : params) {
			String info = String.format("  %s %s  [%s]",
				param.getDataType().getDisplayName(),
				param.getName(),
				param.getVariableStorage().toString());
			JLabel label = new JLabel(info);
			label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
			label.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(label);

			// Show callers that pass values to this parameter
			addParamCallerInfo(panel, func, param);
		}

		functionContentPanel.add(panel);
		functionContentPanel.add(Box.createVerticalStrut(6));
	}

	private void addParamCallerInfo(JPanel panel, Function func, Parameter param) {
		// Find callers of this function
		ReferenceManager refMgr = program.getReferenceManager();
		ReferenceIterator refs = refMgr.getReferencesTo(func.getEntryPoint());

		int callerCount = 0;
		while (refs.hasNext() && callerCount < 10) {
			Reference ref = refs.next();
			if (ref.getReferenceType().isCall()) {
				Function caller =
					program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				if (caller != null && callerCount == 0) {
					JLabel callersLabel = new JLabel("    Called from:");
					callersLabel.setFont(callersLabel.getFont().deriveFont(Font.ITALIC, 10f));
					callersLabel.setForeground(new Color(120, 120, 120));
					callersLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
					panel.add(callersLabel);
				}
				if (caller != null) {
					JLabel callerLabel = new JLabel(
						"      " + caller.getName() + " @ " + ref.getFromAddress());
					callerLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 10));
					callerLabel.setForeground(new Color(70, 130, 180));
					callerLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
					panel.add(callerLabel);
					callerCount++;
				}
			}
		}
	}

	private void addLocalVariablesSection(Function func) {
		Variable[] locals = func.getLocalVariables();
		if (locals.length == 0) {
			return;
		}

		JPanel panel = createSectionPanel("Local Variables (" + locals.length + ")");
		int shown = 0;
		for (Variable v : locals) {
			if (shown >= 40) {
				JLabel more = new JLabel("  ... and " + (locals.length - 40) + " more");
				more.setForeground(Color.GRAY);
				more.setAlignmentX(Component.LEFT_ALIGNMENT);
				panel.add(more);
				break;
			}
			String info = String.format("  %s %s  [%s]",
				v.getDataType().getDisplayName(),
				v.getName(),
				v.getVariableStorage().toString());
			JLabel label = new JLabel(info);
			label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
			label.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(label);
			shown++;
		}

		functionContentPanel.add(panel);
		functionContentPanel.add(Box.createVerticalStrut(6));
	}

	/**
	 * Show global data addresses accessed by this function (reads and writes).
	 */
	private void addGlobalAccessSection(Function func) {
		JPanel panel = createSectionPanel("Global Data Accessed");

		ReferenceManager refMgr = program.getReferenceManager();
		FunctionManager funcMgr = program.getFunctionManager();
		Listing listing = program.getListing();
		SymbolTable symTab = program.getSymbolTable();

		// Find all data references from instructions within this function
		Map<Address, GlobalAccessInfo> accessMap = new LinkedHashMap<>();
		InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
		while (instrIter.hasNext()) {
			Instruction instr = instrIter.next();
			Reference[] refs = instr.getReferencesFrom();
			for (Reference ref : refs) {
				if (!ref.getReferenceType().isData()) {
					continue;
				}

				Address toAddr = ref.getToAddress();

				// Skip references to code (functions)
				if (funcMgr.getFunctionAt(toAddr) != null) {
					continue;
				}

				// Skip references within the same function body
				if (func.getBody().contains(toAddr)) {
					continue;
				}

				if (!accessMap.containsKey(toAddr)) {
					// Get the name and type
					String name = "DAT_" + toAddr.toString();
					Symbol[] syms = symTab.getSymbols(toAddr);
					if (syms.length > 0) {
						name = syms[0].getName();
					}

					String typeName = "(undefined)";
					Data data = listing.getDefinedDataAt(toAddr);
					if (data != null) {
						typeName = data.getDataType().getDisplayName();
						// If it's a string, show the value
						if (data.getValue() instanceof String) {
							continue; // Skip strings - they go in the strings section
						}
					}

					// Find OTHER functions that also reference this same global
					Set<String> otherFunctions = new LinkedHashSet<>();
					ReferenceIterator toRefs = refMgr.getReferencesTo(toAddr);
					int count = 0;
					while (toRefs.hasNext() && count < 50) {
						Reference toRef = toRefs.next();
						Function otherFunc =
							funcMgr.getFunctionContaining(toRef.getFromAddress());
						if (otherFunc != null && !otherFunc.equals(func)) {
							otherFunctions.add(otherFunc.getName());
						}
						count++;
					}

					accessMap.put(toAddr, new GlobalAccessInfo(
						name, toAddr, typeName, ref.getReferenceType().toString(),
						otherFunctions));
				}
			}
		}

		if (accessMap.isEmpty()) {
			JLabel none = new JLabel("  (No global data references found)");
			none.setForeground(Color.GRAY);
			none.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(none);
		}
		else {
			// Sort: most shared first
			List<GlobalAccessInfo> sorted = new ArrayList<>(accessMap.values());
			sorted.sort((a, b) -> Integer.compare(b.otherFunctions.size(),
				a.otherFunctions.size()));

			for (GlobalAccessInfo info : sorted) {
				JLabel varLabel = new JLabel(String.format(
					"  %s @ %s  [%s] (%s)", info.name, info.address,
					info.typeName, info.accessType));
				varLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
				varLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

				// Color based on sharing
				if (info.otherFunctions.size() >= 5) {
					varLabel.setForeground(new Color(244, 67, 54)); // Red = heavily shared
				}
				else if (info.otherFunctions.size() >= 2) {
					varLabel.setForeground(new Color(255, 152, 0)); // Orange = shared
				}
				else if (!info.otherFunctions.isEmpty()) {
					varLabel.setForeground(new Color(33, 150, 243)); // Blue = some sharing
				}

				panel.add(varLabel);

				// Show other functions that share this variable
				if (!info.otherFunctions.isEmpty()) {
					StringBuilder sb = new StringBuilder("    Also used by: ");
					int shown = 0;
					for (String fn : info.otherFunctions) {
						if (shown > 0) {
							sb.append(", ");
						}
						sb.append(fn);
						shown++;
						if (shown >= 8) {
							sb.append(" ... and ").append(info.otherFunctions.size() - 8)
								.append(" more");
							break;
						}
					}
					JLabel sharedLabel = new JLabel(sb.toString());
					sharedLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 10));
					sharedLabel.setForeground(new Color(120, 120, 120));
					sharedLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
					panel.add(sharedLabel);
				}
			}

			panel.add(Box.createVerticalStrut(4));
			JLabel summary = new JLabel(String.format(
				"  Total: %d global data references", accessMap.size()));
			summary.setForeground(Color.GRAY);
			summary.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(summary);
		}

		functionContentPanel.add(panel);
		functionContentPanel.add(Box.createVerticalStrut(6));
	}

	private void addStringsSection(Function func) {
		JPanel panel = createSectionPanel("Strings Referenced");

		Listing listing = program.getListing();
		List<String> strings = new ArrayList<>();

		InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
		while (instrIter.hasNext()) {
			Instruction instr = instrIter.next();
			Reference[] refs = instr.getReferencesFrom();
			for (Reference ref : refs) {
				if (ref.getReferenceType().isData()) {
					Data data = listing.getDefinedDataAt(ref.getToAddress());
					if (data != null && data.getValue() instanceof String) {
						String s = (String) data.getValue();
						if (s.length() > 2) {
							String display = s.length() > 80 ? s.substring(0, 77) + "..." : s;
							display = display.replace("\n", "\\n").replace("\r", "\\r");
							strings.add(String.format("  %s  \"%s\"",
								ref.getToAddress(), display));
						}
					}
				}
			}
		}

		if (strings.isEmpty()) {
			JLabel none = new JLabel("  (No string references)");
			none.setForeground(Color.GRAY);
			none.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(none);
		}
		else {
			int shown = 0;
			for (String s : strings) {
				if (shown >= 20) {
					JLabel more = new JLabel(
						"  ... and " + (strings.size() - 20) + " more");
					more.setForeground(Color.GRAY);
					more.setAlignmentX(Component.LEFT_ALIGNMENT);
					panel.add(more);
					break;
				}
				JLabel label = new JLabel(s);
				label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
				label.setForeground(new Color(147, 112, 219));
				label.setAlignmentX(Component.LEFT_ALIGNMENT);
				panel.add(label);
				shown++;
			}
		}

		functionContentPanel.add(panel);
		functionContentPanel.add(Box.createVerticalStrut(6));
	}

	/**
	 * Show data that this function shares with other functions
	 * (the "connections" through shared variables).
	 */
	private void addSharedDataSection(Function func) {
		JPanel panel = createSectionPanel("Data Connections (Shared Variables)");

		ReferenceManager refMgr = program.getReferenceManager();
		FunctionManager funcMgr = program.getFunctionManager();
		Listing listing = program.getListing();
		SymbolTable symTab = program.getSymbolTable();

		// Build: this function -> global addresses -> other functions
		Map<String, Set<String>> connectionMap = new TreeMap<>(); // otherFunc -> shared vars

		InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
		while (instrIter.hasNext()) {
			Instruction instr = instrIter.next();
			Reference[] refs = instr.getReferencesFrom();
			for (Reference ref : refs) {
				if (!ref.getReferenceType().isData()) {
					continue;
				}

				Address toAddr = ref.getToAddress();
				if (funcMgr.getFunctionAt(toAddr) != null) {
					continue;
				}
				if (func.getBody().contains(toAddr)) {
					continue;
				}

				// Get variable name
				String varName = "DAT_" + toAddr.toString();
				Symbol[] syms = symTab.getSymbols(toAddr);
				if (syms.length > 0) {
					varName = syms[0].getName();
				}

				// Find other functions that reference this same address
				ReferenceIterator toRefs = refMgr.getReferencesTo(toAddr);
				int count = 0;
				while (toRefs.hasNext() && count < 50) {
					Reference toRef = toRefs.next();
					Function otherFunc =
						funcMgr.getFunctionContaining(toRef.getFromAddress());
					if (otherFunc != null && !otherFunc.equals(func)) {
						connectionMap
							.computeIfAbsent(otherFunc.getName(), k -> new TreeSet<>())
							.add(varName);
					}
					count++;
				}
			}
		}

		if (connectionMap.isEmpty()) {
			JLabel none = new JLabel("  (No shared data connections found)");
			none.setForeground(Color.GRAY);
			none.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(none);
		}
		else {
			// Sort by number of shared variables (most connected first)
			List<Map.Entry<String, Set<String>>> sorted =
				new ArrayList<>(connectionMap.entrySet());
			sorted.sort((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()));

			int shown = 0;
			for (Map.Entry<String, Set<String>> entry : sorted) {
				if (shown >= 30) {
					JLabel more = new JLabel(
						"  ... and " + (sorted.size() - 30) + " more connections");
					more.setForeground(Color.GRAY);
					more.setAlignmentX(Component.LEFT_ALIGNMENT);
					panel.add(more);
					break;
				}

				String funcName = entry.getKey();
				Set<String> vars = entry.getValue();

				JLabel connLabel = new JLabel(String.format(
					"  %s  (%d shared variables)", funcName, vars.size()));
				connLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
				connLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

				if (vars.size() >= 5) {
					connLabel.setForeground(new Color(244, 67, 54)); // Red = strong connection
				}
				else if (vars.size() >= 2) {
					connLabel.setForeground(new Color(255, 152, 0)); // Orange
				}
				else {
					connLabel.setForeground(new Color(33, 150, 243)); // Blue
				}
				panel.add(connLabel);

				// List the shared variables
				StringBuilder varList = new StringBuilder("    via: ");
				int varShown = 0;
				for (String v : vars) {
					if (varShown > 0) {
						varList.append(", ");
					}
					varList.append(v);
					varShown++;
					if (varShown >= 6) {
						varList.append(" ...");
						break;
					}
				}
				JLabel varsLabel = new JLabel(varList.toString());
				varsLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 10));
				varsLabel.setForeground(new Color(120, 120, 120));
				varsLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
				panel.add(varsLabel);

				shown++;
			}

			panel.add(Box.createVerticalStrut(4));
			JLabel summary = new JLabel(String.format(
				"  Total: %d connected functions", connectionMap.size()));
			summary.setForeground(Color.GRAY);
			summary.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(summary);
		}

		functionContentPanel.add(panel);
		functionContentPanel.add(Box.createVerticalStrut(6));
	}

	// =======================================================================
	// SHARED DATA TAB
	// =======================================================================

	private void buildSharedDataTab() {
		sharedPanel = new JPanel(new BorderLayout());
		sharedPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

		JPanel headerPanel = new JPanel(new BorderLayout());
		JLabel descLabel = new JLabel(
			"<html>Variables used by 2+ functions. These are key data dependencies " +
			"that connect different parts of the program.</html>");
		descLabel.setBorder(new EmptyBorder(4, 4, 8, 4));
		headerPanel.add(descLabel, BorderLayout.CENTER);

		JButton analyzeBtn = new JButton("Analyze");
		analyzeBtn.addActionListener(e -> analyzeSharedData());
		JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		btnPanel.add(analyzeBtn);
		headerPanel.add(btnPanel, BorderLayout.EAST);

		sharedPanel.add(headerPanel, BorderLayout.NORTH);

		sharedModel = new SharedDataTableModel();
		sharedTable = new JTable(sharedModel);
		sharedTable.setRowHeight(22);
		sharedTable.setAutoCreateRowSorter(true);
		sharedTable.setFillsViewportHeight(true);

		sharedTable.getColumnModel().getColumn(0).setPreferredWidth(180); // Variable
		sharedTable.getColumnModel().getColumn(1).setPreferredWidth(120); // Address
		sharedTable.getColumnModel().getColumn(2).setPreferredWidth(120); // Type
		sharedTable.getColumnModel().getColumn(3).setPreferredWidth(60);  // Function Count
		sharedTable.getColumnModel().getColumn(4).setPreferredWidth(300); // Functions

		sharedTable.getColumnModel().getColumn(3).setCellRenderer(new UsageCountRenderer());

		JScrollPane scrollPane = new JScrollPane(sharedTable);
		sharedPanel.add(scrollPane, BorderLayout.CENTER);

		sharedStatusLabel = new JLabel(" ");
		sharedStatusLabel.setBorder(new EmptyBorder(4, 4, 4, 4));
		sharedPanel.add(sharedStatusLabel, BorderLayout.SOUTH);
	}

	private void analyzeSharedData() {
		if (program == null || analysisRunning) {
			return;
		}
		analysisRunning = true;
		sharedStatusLabel.setText("Analyzing shared data...");

		new Thread(() -> {
			try {
				List<GlobalVarEntry> all = scanGlobalVariables();
				// Filter to only variables used by 2+ functions
				List<GlobalVarEntry> shared = new ArrayList<>();
				for (GlobalVarEntry entry : all) {
					if (entry.usageCount >= 2) {
						shared.add(entry);
					}
				}

				SwingUtilities.invokeLater(() -> {
					sharedModel.setEntries(shared);
					sharedStatusLabel.setText(String.format(
						"Found %d shared variables (used by 2+ functions)", shared.size()));
					analysisRunning = false;
				});
			}
			catch (Exception e) {
				Msg.error(this, "Error analyzing shared data", e);
				SwingUtilities.invokeLater(() -> {
					sharedStatusLabel.setText("Error: " + e.getMessage());
					analysisRunning = false;
				});
			}
		}, "VariableTracker-SharedAnalysis").start();
	}

	// =======================================================================
	// UI HELPERS
	// =======================================================================

	private JPanel createSectionPanel(String title) {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(BorderFactory.createCompoundBorder(
			BorderFactory.createTitledBorder(
				BorderFactory.createLineBorder(new Color(200, 200, 200)),
				title,
				TitledBorder.LEFT,
				TitledBorder.TOP),
			new EmptyBorder(4, 6, 4, 6)));
		panel.setAlignmentX(Component.LEFT_ALIGNMENT);
		panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
		return panel;
	}

	private void addInfoRow(JPanel panel, String label, String value) {
		JPanel row = new JPanel(new BorderLayout());
		row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 18));
		row.setAlignmentX(Component.LEFT_ALIGNMENT);

		JLabel keyLabel = new JLabel("  " + label + ": ");
		keyLabel.setFont(keyLabel.getFont().deriveFont(Font.BOLD, 11f));

		JLabel valLabel = new JLabel(value);
		valLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

		row.add(keyLabel, BorderLayout.WEST);
		row.add(valLabel, BorderLayout.CENTER);
		panel.add(row);
	}

	void dispose() {
		removeFromTool();
	}

	// =======================================================================
	// DATA CLASSES
	// =======================================================================

	private static class GlobalVarEntry {
		final String name;
		final Address address;
		final String typeName;
		final int usageCount;
		final Set<String> usingFunctions;

		GlobalVarEntry(String name, Address address, String typeName,
				int usageCount, Set<String> usingFunctions) {
			this.name = name;
			this.address = address;
			this.typeName = typeName;
			this.usageCount = usageCount;
			this.usingFunctions = usingFunctions;
		}
	}

	private static class GlobalAccessInfo {
		final String name;
		final Address address;
		final String typeName;
		final String accessType;
		final Set<String> otherFunctions;

		GlobalAccessInfo(String name, Address address, String typeName,
				String accessType, Set<String> otherFunctions) {
			this.name = name;
			this.address = address;
			this.typeName = typeName;
			this.accessType = accessType;
			this.otherFunctions = otherFunctions;
		}
	}

	// =======================================================================
	// TABLE MODELS
	// =======================================================================

	private static class GlobalsTableModel extends AbstractTableModel {
		private static final String[] COLUMNS =
			{ "Variable", "Address", "Type", "Used By", "Functions" };
		private List<GlobalVarEntry> entries = new ArrayList<>();

		void setEntries(List<GlobalVarEntry> newEntries) {
			this.entries = newEntries;
			fireTableDataChanged();
		}

		void clear() {
			entries.clear();
			fireTableDataChanged();
		}

		@Override
		public int getRowCount() {
			return entries.size();
		}

		@Override
		public int getColumnCount() {
			return COLUMNS.length;
		}

		@Override
		public String getColumnName(int column) {
			return COLUMNS[column];
		}

		@Override
		public Class<?> getColumnClass(int column) {
			if (column == 3) {
				return Integer.class;
			}
			return String.class;
		}

		@Override
		public Object getValueAt(int row, int column) {
			GlobalVarEntry entry = entries.get(row);
			switch (column) {
				case 0: return entry.name;
				case 1: return entry.address.toString();
				case 2: return entry.typeName;
				case 3: return entry.usageCount;
				case 4: return String.join(", ", entry.usingFunctions);
				default: return "";
			}
		}
	}

	private static class SharedDataTableModel extends AbstractTableModel {
		private static final String[] COLUMNS =
			{ "Variable", "Address", "Type", "Fn Count", "Functions" };
		private List<GlobalVarEntry> entries = new ArrayList<>();

		void setEntries(List<GlobalVarEntry> newEntries) {
			this.entries = newEntries;
			fireTableDataChanged();
		}

		void clear() {
			entries.clear();
			fireTableDataChanged();
		}

		@Override
		public int getRowCount() {
			return entries.size();
		}

		@Override
		public int getColumnCount() {
			return COLUMNS.length;
		}

		@Override
		public String getColumnName(int column) {
			return COLUMNS[column];
		}

		@Override
		public Class<?> getColumnClass(int column) {
			if (column == 3) {
				return Integer.class;
			}
			return String.class;
		}

		@Override
		public Object getValueAt(int row, int column) {
			GlobalVarEntry entry = entries.get(row);
			switch (column) {
				case 0: return entry.name;
				case 1: return entry.address.toString();
				case 2: return entry.typeName;
				case 3: return entry.usageCount;
				case 4: return String.join(", ", entry.usingFunctions);
				default: return "";
			}
		}
	}

	/**
	 * Renderer that colors usage count cells by intensity:
	 * Red for high usage, orange for medium, blue for low.
	 */
	private static class UsageCountRenderer extends DefaultTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean isSelected, boolean hasFocus, int row, int column) {
			Component c = super.getTableCellRendererComponent(
				table, value, isSelected, hasFocus, row, column);

			if (!isSelected && value instanceof Integer) {
				int count = (Integer) value;
				if (count >= 10) {
					c.setForeground(new Color(244, 67, 54));  // Red
					c.setFont(c.getFont().deriveFont(Font.BOLD));
				}
				else if (count >= 5) {
					c.setForeground(new Color(255, 152, 0));  // Orange
					c.setFont(c.getFont().deriveFont(Font.BOLD));
				}
				else if (count >= 2) {
					c.setForeground(new Color(33, 150, 243)); // Blue
				}
				else {
					c.setForeground(table.getForeground());
				}
			}

			setHorizontalAlignment(CENTER);
			return c;
		}
	}
}
