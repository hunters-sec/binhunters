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
package ghidra.app.plugin.core.contextsidebar;

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

/**
 * Provider for the context sidebar — a panel that dynamically shows
 * relevant information based on the current cursor position.
 */
public class ContextSidebarProvider extends ComponentProviderAdapter {

	private static final String TITLE = "Context";
	private static final int MAX_XREFS = 50;
	private static final int MAX_STRINGS = 20;

	private ContextSidebarPlugin plugin;
	private Program program;
	private JPanel mainPanel;
	private JPanel contentPanel;
	private Address lastAddress;

	ContextSidebarProvider(ContextSidebarPlugin plugin) {
		super(plugin.getTool(), TITLE, plugin.getName());
		this.plugin = plugin;

		setTitle(TITLE);
		setHelpLocation(new HelpLocation(plugin.getName(), plugin.getName()));

		mainPanel = new JPanel(new BorderLayout());
		contentPanel = new JPanel();
		contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));

		JScrollPane scrollPane = new JScrollPane(contentPanel);
		scrollPane.getVerticalScrollBar().setUnitIncrement(16);
		mainPanel.add(scrollPane, BorderLayout.CENTER);

		showEmptyState("No program loaded");
		addToTool();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	void setProgram(Program newProgram) {
		this.program = newProgram;
		this.lastAddress = null;
		if (program == null) {
			showEmptyState("No program loaded");
		}
		else {
			showEmptyState("Navigate to a location to see context");
		}
	}

	void locationChanged(ProgramLocation loc) {
		if (program == null || loc == null) {
			return;
		}

		Address addr = loc.getAddress();
		if (addr == null || addr.equals(lastAddress)) {
			return;
		}
		lastAddress = addr;

		rebuildForAddress(addr);
	}

	private void showEmptyState(String message) {
		contentPanel.removeAll();
		JLabel emptyLabel = new JLabel(message, SwingConstants.CENTER);
		emptyLabel.setFont(emptyLabel.getFont().deriveFont(13f));
		emptyLabel.setForeground(Color.GRAY);
		emptyLabel.setBorder(new EmptyBorder(30, 15, 30, 15));
		contentPanel.add(emptyLabel);
		contentPanel.revalidate();
		contentPanel.repaint();
	}

	private void rebuildForAddress(Address addr) {
		contentPanel.removeAll();
		contentPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

		// Determine what we're looking at
		FunctionManager funcMgr = program.getFunctionManager();
		Function function = funcMgr.getFunctionAt(addr);
		Function containingFunction = funcMgr.getFunctionContaining(addr);

		if (function != null) {
			// Cursor is ON a function entry point
			buildFunctionContext(function);
		}
		else if (containingFunction != null) {
			// Cursor is inside a function
			buildAddressContext(addr, containingFunction);
		}
		else {
			// Cursor is on data or non-function code
			buildDataContext(addr);
		}

		// Always show xrefs for the current address
		addXrefSection(addr);

		contentPanel.add(Box.createVerticalGlue());
		contentPanel.revalidate();
		contentPanel.repaint();
	}

	// -----------------------------------------------------------------------
	// Function context (cursor on function entry)
	// -----------------------------------------------------------------------

	private void buildFunctionContext(Function func) {
		// Header
		JPanel header = createSectionPanel("Function");
		JLabel nameLabel = new JLabel("  " + func.getName());
		nameLabel.setFont(nameLabel.getFont().deriveFont(Font.BOLD, 14f));
		nameLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
		header.add(nameLabel);
		header.add(Box.createVerticalStrut(4));

		// Signature
		JLabel sigLabel = new JLabel("  " + func.getPrototypeString(true, false));
		sigLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
		sigLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
		header.add(sigLabel);
		header.add(Box.createVerticalStrut(4));

		addInfoRow(header, "Entry", func.getEntryPoint().toString());
		addInfoRow(header, "Size", String.format("0x%X bytes", func.getBody().getNumAddresses()));
		addInfoRow(header, "Convention", func.getCallingConventionName());
		if (func.isThunk()) {
			Function thunked = func.getThunkedFunction(true);
			addInfoRow(header, "Thunks", thunked != null ? thunked.getName() : "unknown");
		}

		contentPanel.add(header);
		contentPanel.add(Box.createVerticalStrut(6));

		// Callers (who calls this function)
		addCallersSection(func);

		// Callees (what this function calls)
		addCalleesSection(func);

		// Parameters
		addParametersSection(func);

		// Local variables
		addLocalVariablesSection(func);

		// Strings in this function
		addFunctionStringsSection(func);
	}

	private void addCallersSection(Function func) {
		JPanel panel = createSectionPanel("Incoming Calls (Callers)");

		ReferenceManager refMgr = program.getReferenceManager();
		ReferenceIterator refs = refMgr.getReferencesTo(func.getEntryPoint());

		Set<String> callers = new LinkedHashSet<>();
		while (refs.hasNext()) {
			Reference ref = refs.next();
			if (ref.getReferenceType().isCall()) {
				Function caller =
					program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				if (caller != null) {
					callers.add(String.format("  %s @ %s",
						caller.getName(), ref.getFromAddress()));
				}
			}
		}

		if (callers.isEmpty()) {
			JLabel none = new JLabel("  (No callers found)");
			none.setForeground(Color.GRAY);
			none.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(none);
		}
		else {
			for (String caller : callers) {
				JLabel label = new JLabel(caller);
				label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
				label.setForeground(new Color(70, 130, 180));
				label.setAlignmentX(Component.LEFT_ALIGNMENT);
				panel.add(label);
			}
		}

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(6));
	}

	private void addCalleesSection(Function func) {
		JPanel panel = createSectionPanel("Outgoing Calls (Callees)");

		Set<Function> callees = func.getCalledFunctions(null);
		if (callees.isEmpty()) {
			JLabel none = new JLabel("  (No outgoing calls)");
			none.setForeground(Color.GRAY);
			none.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(none);
		}
		else {
			for (Function callee : callees) {
				String info = String.format("  %s @ %s",
					callee.getName(), callee.getEntryPoint());
				JLabel label = new JLabel(info);
				label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
				label.setForeground(new Color(60, 179, 113));
				label.setAlignmentX(Component.LEFT_ALIGNMENT);
				panel.add(label);
			}
		}

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(6));
	}

	private void addParametersSection(Function func) {
		Parameter[] params = func.getParameters();
		if (params.length == 0) {
			return;
		}

		JPanel panel = createSectionPanel("Parameters");
		for (Parameter param : params) {
			String info = String.format("  %s %s  [%s]",
				param.getDataType().getDisplayName(),
				param.getName(),
				param.getVariableStorage().toString());
			JLabel label = new JLabel(info);
			label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
			label.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(label);
		}

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(6));
	}

	private void addLocalVariablesSection(Function func) {
		Variable[] locals = func.getLocalVariables();
		if (locals.length == 0) {
			return;
		}

		JPanel panel = createSectionPanel("Local Variables (" + locals.length + ")");
		int shown = 0;
		for (Variable v : locals) {
			if (shown >= 30) {
				JLabel more = new JLabel("  ... and " + (locals.length - 30) + " more");
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

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(6));
	}

	private void addFunctionStringsSection(Function func) {
		JPanel panel = createSectionPanel("Strings Referenced");

		List<String> strings = new ArrayList<>();
		// Find all data references from within this function
		ReferenceManager refMgr = program.getReferenceManager();
		Listing listing = program.getListing();

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
							strings.add(String.format("  %s \"%s\"",
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
				if (shown >= MAX_STRINGS) {
					JLabel more = new JLabel(
						"  ... and " + (strings.size() - MAX_STRINGS) + " more");
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

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(6));
	}

	// -----------------------------------------------------------------------
	// Address context (cursor inside a function, not on entry)
	// -----------------------------------------------------------------------

	private void buildAddressContext(Address addr, Function containingFunc) {
		JPanel header = createSectionPanel("Address Context");
		addInfoRow(header, "Address", addr.toString());
		addInfoRow(header, "In Function", containingFunc.getName());

		// Show the instruction or data at this address
		Listing listing = program.getListing();
		Instruction instr = listing.getInstructionAt(addr);
		if (instr != null) {
			addInfoRow(header, "Instruction", instr.toString());
		}
		else {
			Data data = listing.getDefinedDataAt(addr);
			if (data != null) {
				addInfoRow(header, "Data", data.getDataType().getDisplayName());
				if (data.getValue() != null) {
					String val = data.getValue().toString();
					if (val.length() > 60) {
						val = val.substring(0, 57) + "...";
					}
					addInfoRow(header, "Value", val);
				}
			}
		}

		contentPanel.add(header);
		contentPanel.add(Box.createVerticalStrut(6));

		// Compact function info
		JPanel funcInfo = createSectionPanel("Containing Function");
		JLabel sig = new JLabel("  " + containingFunc.getPrototypeString(true, false));
		sig.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
		sig.setAlignmentX(Component.LEFT_ALIGNMENT);
		funcInfo.add(sig);
		addInfoRow(funcInfo, "Entry", containingFunc.getEntryPoint().toString());

		contentPanel.add(funcInfo);
		contentPanel.add(Box.createVerticalStrut(6));
	}

	// -----------------------------------------------------------------------
	// Data context (cursor on data outside functions)
	// -----------------------------------------------------------------------

	private void buildDataContext(Address addr) {
		JPanel header = createSectionPanel("Data Context");
		addInfoRow(header, "Address", addr.toString());

		Listing listing = program.getListing();
		Data data = listing.getDefinedDataAt(addr);
		if (data != null) {
			addInfoRow(header, "Type", data.getDataType().getDisplayName());
			addInfoRow(header, "Size", String.valueOf(data.getLength()));
			if (data.getValue() != null) {
				String val = data.getValue().toString();
				if (val.length() > 80) {
					val = val.substring(0, 77) + "...";
				}
				val = val.replace("\n", "\\n").replace("\r", "\\r");
				addInfoRow(header, "Value", val);
			}
		}
		else {
			addInfoRow(header, "Type", "(undefined)");
		}

		// Show symbol info if any
		SymbolTable symTab = program.getSymbolTable();
		Symbol[] symbols = symTab.getSymbols(addr);
		if (symbols.length > 0) {
			header.add(Box.createVerticalStrut(4));
			for (Symbol sym : symbols) {
				addInfoRow(header, "Symbol", sym.getName() + " (" + sym.getSymbolType() + ")");
			}
		}

		contentPanel.add(header);
		contentPanel.add(Box.createVerticalStrut(6));
	}

	// -----------------------------------------------------------------------
	// Xref section (shown for all contexts)
	// -----------------------------------------------------------------------

	private void addXrefSection(Address addr) {
		JPanel panel = createSectionPanel("Cross References");

		ReferenceManager refMgr = program.getReferenceManager();

		// References TO this address (returns ReferenceIterator)
		List<Reference> refsToList = new ArrayList<>();
		ReferenceIterator refsToIter = refMgr.getReferencesTo(addr);
		while (refsToIter.hasNext()) {
			refsToList.add(refsToIter.next());
		}

		if (!refsToList.isEmpty()) {
			JLabel toHeader = new JLabel("  References TO (" + refsToList.size() + "):");
			toHeader.setFont(toHeader.getFont().deriveFont(Font.BOLD, 11f));
			toHeader.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(toHeader);

			int shown = 0;
			for (Reference ref : refsToList) {
				if (shown >= MAX_XREFS) {
					JLabel more = new JLabel(
						"    ... and " + (refsToList.size() - MAX_XREFS) + " more");
					more.setForeground(Color.GRAY);
					more.setAlignmentX(Component.LEFT_ALIGNMENT);
					panel.add(more);
					break;
				}

				Function fromFunc =
					program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
				String funcName = (fromFunc != null) ? fromFunc.getName() : "?";

				String info = String.format("    %s [%s] from %s",
					ref.getFromAddress(), ref.getReferenceType(), funcName);
				JLabel label = new JLabel(info);
				label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
				label.setAlignmentX(Component.LEFT_ALIGNMENT);
				panel.add(label);
				shown++;
			}
		}

		// References FROM this address (returns Reference[])
		Reference[] refsFrom = refMgr.getReferencesFrom(addr);
		if (refsFrom.length > 0) {
			if (!refsToList.isEmpty()) {
				panel.add(Box.createVerticalStrut(4));
			}
			JLabel fromHeader = new JLabel("  References FROM (" + refsFrom.length + "):");
			fromHeader.setFont(fromHeader.getFont().deriveFont(Font.BOLD, 11f));
			fromHeader.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(fromHeader);

			for (Reference ref : refsFrom) {
				String info = String.format("    -> %s [%s]",
					ref.getToAddress(), ref.getReferenceType());
				JLabel label = new JLabel(info);
				label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
				label.setAlignmentX(Component.LEFT_ALIGNMENT);
				panel.add(label);
			}
		}

		if (refsToList.isEmpty() && refsFrom.length == 0) {
			JLabel none = new JLabel("  (No cross references)");
			none.setForeground(Color.GRAY);
			none.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(none);
		}

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(6));
	}

	// -----------------------------------------------------------------------
	// UI Helpers
	// -----------------------------------------------------------------------

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
}
