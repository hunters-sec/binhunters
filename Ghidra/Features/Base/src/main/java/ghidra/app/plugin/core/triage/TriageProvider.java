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
package ghidra.app.plugin.core.triage;

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.HelpLocation;

/**
 * Provider for the triage panel that shows a comprehensive binary overview.
 * Displays: binary metadata, memory section map, function statistics,
 * notable strings, import summary, and code classification.
 */
public class TriageProvider extends ComponentProviderAdapter {

	private static final String TITLE = "Triage";

	private TriagePlugin plugin;
	private Program program;
	private JPanel mainPanel;
	private JPanel contentPanel;

	// Section colors
	private static final Color COLOR_TEXT = new Color(70, 130, 180);    // Steel blue
	private static final Color COLOR_DATA = new Color(60, 179, 113);    // Medium sea green
	private static final Color COLOR_RODATA = new Color(147, 112, 219); // Medium purple
	private static final Color COLOR_BSS = new Color(210, 180, 140);    // Tan
	private static final Color COLOR_OTHER = new Color(169, 169, 169);  // Dark gray

	TriageProvider(TriagePlugin plugin) {
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

		showEmptyState();
		addToTool();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	void setProgram(Program newProgram) {
		this.program = newProgram;
		if (program != null) {
			rebuildPanel();
		}
		else {
			showEmptyState();
		}
	}

	private void showEmptyState() {
		contentPanel.removeAll();
		JLabel emptyLabel = new JLabel("No program loaded. Open a binary to see triage info.",
			SwingConstants.CENTER);
		emptyLabel.setFont(emptyLabel.getFont().deriveFont(14f));
		emptyLabel.setForeground(Color.GRAY);
		emptyLabel.setBorder(new EmptyBorder(40, 20, 40, 20));
		contentPanel.add(emptyLabel);
		contentPanel.revalidate();
		contentPanel.repaint();
	}

	private void rebuildPanel() {
		contentPanel.removeAll();
		contentPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

		addMetadataSection();
		addSectionMapSection();
		addFunctionStatsSection();
		addStringHighlightsSection();
		addImportSummarySection();
		addCodeClassificationSection();

		contentPanel.revalidate();
		contentPanel.repaint();
	}

	// -----------------------------------------------------------------------
	// Binary Metadata
	// -----------------------------------------------------------------------

	private void addMetadataSection() {
		JPanel panel = createSectionPanel("Binary Metadata");

		addInfoRow(panel, "Name", program.getName());
		addInfoRow(panel, "Format", program.getExecutableFormat());
		addInfoRow(panel, "Language",
			program.getLanguage().getLanguageDescription().getDescription());
		addInfoRow(panel, "Compiler", program.getCompilerSpec().getCompilerSpecID().toString());
		addInfoRow(panel, "Endianness",
			program.getLanguage().isBigEndian() ? "Big Endian" : "Little Endian");
		addInfoRow(panel, "Address Size",
			program.getDefaultPointerSize() * 8 + "-bit");
		addInfoRow(panel, "Image Base", program.getImageBase().toString());
		addInfoRow(panel, "Executable Path",
			program.getExecutablePath() != null ? program.getExecutablePath() : "N/A");

		// MD5 if available
		String md5 = program.getExecutableMD5();
		if (md5 != null && !md5.isEmpty()) {
			addInfoRow(panel, "MD5", md5);
		}

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(8));
	}

	// -----------------------------------------------------------------------
	// Section Map (visual bar)
	// -----------------------------------------------------------------------

	private void addSectionMapSection() {
		JPanel panel = createSectionPanel("Memory Sections");

		MemoryBlock[] blocks = program.getMemory().getBlocks();
		long totalSizeCalc = 0;
		for (MemoryBlock block : blocks) {
			totalSizeCalc += block.getSize();
		}
		final long totalSize = totalSizeCalc;

		// Visual section bar
		JPanel barPanel = new JPanel() {
			@Override
			protected void paintComponent(Graphics g) {
				super.paintComponent(g);
				Graphics2D g2 = (Graphics2D) g;
				g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
					RenderingHints.VALUE_ANTIALIAS_ON);

				int width = getWidth() - 4;
				int height = getHeight() - 4;
				int x = 2;

				for (MemoryBlock block : blocks) {
					if (totalSize == 0) {
						break;
					}
					int blockWidth =
						Math.max(2, (int) (((double) block.getSize() / totalSize) * width));
					Color color = getSectionColor(block);
					g2.setColor(color);
					g2.fillRoundRect(x, 2, blockWidth, height, 4, 4);
					g2.setColor(color.darker());
					g2.drawRoundRect(x, 2, blockWidth, height, 4, 4);

					// Label if block is wide enough
					if (blockWidth > 30) {
						g2.setColor(Color.WHITE);
						g2.setFont(g2.getFont().deriveFont(9f));
						FontMetrics fm = g2.getFontMetrics();
						String name = block.getName();
						if (fm.stringWidth(name) < blockWidth - 4) {
							g2.drawString(name, x + 3, 2 + height / 2 + fm.getAscent() / 2 - 1);
						}
					}
					x += blockWidth + 1;
				}
			}
		};
		barPanel.setPreferredSize(new Dimension(0, 28));
		barPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
		panel.add(barPanel);
		panel.add(Box.createVerticalStrut(6));

		// Section details table
		for (MemoryBlock block : blocks) {
			String perms = "";
			perms += block.isRead() ? "r" : "-";
			perms += block.isWrite() ? "w" : "-";
			perms += block.isExecute() ? "x" : "-";

			String info = String.format("%-16s %s  size: 0x%X  [%s]",
				block.getName(), block.getStart(), block.getSize(), perms);

			JLabel label = new JLabel(info);
			label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
			label.setForeground(getSectionColor(block));
			label.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(label);
		}

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(8));
	}

	private Color getSectionColor(MemoryBlock block) {
		String name = block.getName().toLowerCase();
		if (name.contains("text") || name.contains("code")) {
			return COLOR_TEXT;
		}
		if (name.contains("rodata") || name.contains("const") || name.contains("cstring")) {
			return COLOR_RODATA;
		}
		if (name.contains("data")) {
			return COLOR_DATA;
		}
		if (name.contains("bss")) {
			return COLOR_BSS;
		}
		return COLOR_OTHER;
	}

	// -----------------------------------------------------------------------
	// Function Statistics
	// -----------------------------------------------------------------------

	private void addFunctionStatsSection() {
		JPanel panel = createSectionPanel("Function Statistics");

		FunctionManager funcMgr = program.getFunctionManager();
		int total = funcMgr.getFunctionCount();
		int named = 0;
		int autoGenerated = 0;
		int thunks = 0;
		int external = 0;
		long totalCodeSize = 0;
		long largestSize = 0;
		String largestName = "";

		FunctionIterator iter = funcMgr.getFunctions(true);
		while (iter.hasNext()) {
			Function func = iter.next();
			long size = func.getBody().getNumAddresses();
			totalCodeSize += size;
			if (size > largestSize) {
				largestSize = size;
				largestName = func.getName();
			}

			if (func.isThunk()) {
				thunks++;
			}
			else if (func.isExternal()) {
				external++;
			}
			else if (func.getName().startsWith("FUN_")) {
				autoGenerated++;
			}
			else {
				named++;
			}
		}

		addInfoRow(panel, "Total Functions", String.valueOf(total));
		addInfoRow(panel, "Named (user)", String.valueOf(named));
		addInfoRow(panel, "Auto-generated", String.valueOf(autoGenerated));
		addInfoRow(panel, "Thunks", String.valueOf(thunks));
		addInfoRow(panel, "External", String.valueOf(external));
		panel.add(Box.createVerticalStrut(4));

		if (total > 0) {
			long avgSize = totalCodeSize / total;
			addInfoRow(panel, "Avg Function Size", String.format("0x%X bytes", avgSize));
			addInfoRow(panel, "Largest Function",
				String.format("%s (0x%X bytes)", largestName, largestSize));
		}

		// Coverage bar: named vs auto
		if (total > 0) {
			panel.add(Box.createVerticalStrut(8));
			int namedPct = (int) ((named * 100.0) / total);
			JLabel coverageLabel = new JLabel(
				String.format("Analysis Coverage: %d%% named", namedPct));
			coverageLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(coverageLabel);

			JProgressBar coverageBar = new JProgressBar(0, total);
			coverageBar.setValue(named);
			coverageBar.setStringPainted(true);
			coverageBar.setString(named + " / " + total);
			coverageBar.setForeground(new Color(76, 175, 80));
			coverageBar.setMaximumSize(new Dimension(Integer.MAX_VALUE, 20));
			coverageBar.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(coverageBar);
		}

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(8));
	}

	// -----------------------------------------------------------------------
	// String Highlights
	// -----------------------------------------------------------------------

	private void addStringHighlightsSection() {
		JPanel panel = createSectionPanel("Notable Strings (Top 30)");

		List<StringEntry> allStrings = new ArrayList<>();
		for (Data stringData : DefinedStringIterator.forProgram(program)) {
			Object value = stringData.getValue();
			if (value == null) {
				continue;
			}
			String str = value.toString();
			if (str.length() < 4) {
				continue; // Skip very short strings
			}
			int score = scoreString(str);
			allStrings.add(new StringEntry(stringData.getAddress(), str, score));
		}

		// Sort by interestingness score (highest first)
		allStrings.sort((a, b) -> Integer.compare(b.score, a.score));

		int shown = 0;
		for (StringEntry entry : allStrings) {
			if (shown >= 30) {
				break;
			}

			String display = entry.value;
			if (display.length() > 100) {
				display = display.substring(0, 97) + "...";
			}
			display = display.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");

			JLabel label = new JLabel(
				String.format("%s  %s", entry.address, display));
			label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
			label.setAlignmentX(Component.LEFT_ALIGNMENT);

			// Color-code by category
			if (isNetworkRelated(entry.value)) {
				label.setForeground(new Color(255, 87, 34)); // Orange-red
			}
			else if (isFilePath(entry.value)) {
				label.setForeground(new Color(76, 175, 80)); // Green
			}
			else if (isCryptoRelated(entry.value)) {
				label.setForeground(new Color(233, 30, 99)); // Pink
			}
			else if (isErrorMessage(entry.value)) {
				label.setForeground(new Color(156, 39, 176)); // Purple
			}

			panel.add(label);
			shown++;
		}

		if (allStrings.isEmpty()) {
			JLabel empty = new JLabel("  (No strings found)");
			empty.setForeground(Color.GRAY);
			panel.add(empty);
		}
		else {
			panel.add(Box.createVerticalStrut(4));
			JLabel totalLabel = new JLabel("  Total defined strings: " + allStrings.size());
			totalLabel.setForeground(Color.GRAY);
			totalLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(totalLabel);
		}

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(8));
	}

	/**
	 * Score strings by "interestingness" for RE triage.
	 * Higher score = more interesting for a reverse engineer.
	 */
	private int scoreString(String s) {
		int score = 0;
		String lower = s.toLowerCase();

		// URLs, IPs, domains
		if (lower.contains("http://") || lower.contains("https://")) {
			score += 100;
		}
		if (lower.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) {
			score += 80;
		}

		// File paths
		if (lower.contains("/etc/") || lower.contains("c:\\") ||
			lower.contains("/usr/") || lower.contains("/tmp/")) {
			score += 70;
		}

		// Crypto-related
		if (lower.contains("aes") || lower.contains("rsa") ||
			lower.contains("sha") || lower.contains("md5") ||
			lower.contains("encrypt") || lower.contains("decrypt") ||
			lower.contains("cipher") || lower.contains("ssl") ||
			lower.contains("certificate") || lower.contains("private key")) {
			score += 90;
		}

		// Network/socket
		if (lower.contains("socket") || lower.contains("connect") ||
			lower.contains("bind") || lower.contains("listen") ||
			lower.contains("recv") || lower.contains("send") ||
			lower.contains("port")) {
			score += 60;
		}

		// Error messages (often reveal logic)
		if (lower.contains("error") || lower.contains("fail") ||
			lower.contains("invalid") || lower.contains("denied") ||
			lower.contains("unauthorized") || lower.contains("exception")) {
			score += 50;
		}

		// Process/system
		if (lower.contains("exec") || lower.contains("spawn") ||
			lower.contains("system(") || lower.contains("popen") ||
			lower.contains("fork") || lower.contains("shell")) {
			score += 85;
		}

		// Registry (Windows)
		if (lower.contains("hkey_") || lower.contains("\\software\\") ||
			lower.contains("regist")) {
			score += 70;
		}

		// Format strings (reveal data handling)
		if (lower.contains("%s") || lower.contains("%d") || lower.contains("%x")) {
			score += 20;
		}

		// Longer strings tend to be more informative
		if (s.length() > 20) {
			score += 10;
		}
		if (s.length() > 50) {
			score += 10;
		}

		return score;
	}

	private boolean isNetworkRelated(String s) {
		String lower = s.toLowerCase();
		return lower.contains("http") || lower.contains("socket") ||
			lower.contains("connect") || lower.contains("url") ||
			lower.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*");
	}

	private boolean isFilePath(String s) {
		return s.contains("/") && s.length() > 5 && !s.contains("http");
	}

	private boolean isCryptoRelated(String s) {
		String lower = s.toLowerCase();
		return lower.contains("aes") || lower.contains("rsa") || lower.contains("encrypt") ||
			lower.contains("cipher") || lower.contains("ssl") || lower.contains("certificate");
	}

	private boolean isErrorMessage(String s) {
		String lower = s.toLowerCase();
		return lower.contains("error") || lower.contains("fail") || lower.contains("invalid") ||
			lower.contains("denied");
	}

	// -----------------------------------------------------------------------
	// Import Summary
	// -----------------------------------------------------------------------

	private void addImportSummarySection() {
		JPanel panel = createSectionPanel("Import Summary");

		SymbolTable symbolTable = program.getSymbolTable();
		Map<String, List<String>> byLibrary = new TreeMap<>();
		Map<String, Integer> byCategory = new TreeMap<>();

		int totalImports = 0;
		SymbolIterator externalSymbols = symbolTable.getExternalSymbols();
		while (externalSymbols.hasNext()) {
			Symbol sym = externalSymbols.next();
			Namespace parent = sym.getParentNamespace();
			String libName = (parent != null && !parent.isGlobal()) ? parent.getName() : "UNKNOWN";

			byLibrary.computeIfAbsent(libName, k -> new ArrayList<>()).add(sym.getName());

			// Categorize by API type
			String category = categorizeImport(sym.getName());
			byCategory.merge(category, 1, Integer::sum);

			totalImports++;
		}

		addInfoRow(panel, "Total Imports", String.valueOf(totalImports));
		addInfoRow(panel, "Libraries", String.valueOf(byLibrary.size()));
		panel.add(Box.createVerticalStrut(6));

		// Category breakdown
		if (!byCategory.isEmpty()) {
			JLabel catHeader = new JLabel("  API Categories:");
			catHeader.setFont(catHeader.getFont().deriveFont(Font.BOLD));
			catHeader.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(catHeader);

			for (Map.Entry<String, Integer> entry : byCategory.entrySet()) {
				JLabel catLabel = new JLabel(
					String.format("    %-20s %d", entry.getKey(), entry.getValue()));
				catLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
				catLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
				panel.add(catLabel);
			}
		}

		panel.add(Box.createVerticalStrut(6));

		// Top libraries
		if (!byLibrary.isEmpty()) {
			JLabel libHeader = new JLabel("  Libraries:");
			libHeader.setFont(libHeader.getFont().deriveFont(Font.BOLD));
			libHeader.setAlignmentX(Component.LEFT_ALIGNMENT);
			panel.add(libHeader);

			for (Map.Entry<String, List<String>> entry : byLibrary.entrySet()) {
				JLabel libLabel = new JLabel(String.format("    %-30s (%d symbols)",
					entry.getKey(), entry.getValue().size()));
				libLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
				libLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
				panel.add(libLabel);
			}
		}

		contentPanel.add(panel);
		contentPanel.add(Box.createVerticalStrut(8));
	}

	/**
	 * Categorize import functions by their purpose.
	 */
	private String categorizeImport(String name) {
		String lower = name.toLowerCase();

		if (lower.contains("socket") || lower.contains("connect") || lower.contains("bind") ||
			lower.contains("listen") || lower.contains("send") || lower.contains("recv") ||
			lower.contains("http") || lower.contains("url") || lower.contains("inet") ||
			lower.contains("gethost") || lower.contains("dns")) {
			return "Network";
		}
		if (lower.contains("file") || lower.contains("open") || lower.contains("read") ||
			lower.contains("write") || lower.contains("close") || lower.contains("stat") ||
			lower.contains("fopen") || lower.contains("fread") || lower.contains("fwrite") ||
			lower.contains("mkdir") || lower.contains("unlink") || lower.contains("rename")) {
			return "File I/O";
		}
		if (lower.contains("crypt") || lower.contains("aes") || lower.contains("rsa") ||
			lower.contains("ssl") || lower.contains("hash") || lower.contains("sha") ||
			lower.contains("md5") || lower.contains("cipher") || lower.contains("cert")) {
			return "Crypto/SSL";
		}
		if (lower.contains("alloc") || lower.contains("malloc") || lower.contains("free") ||
			lower.contains("realloc") || lower.contains("mmap") || lower.contains("heap") ||
			lower.contains("memcpy") || lower.contains("memset") || lower.contains("memmove")) {
			return "Memory";
		}
		if (lower.contains("exec") || lower.contains("fork") || lower.contains("spawn") ||
			lower.contains("process") || lower.contains("thread") || lower.contains("mutex") ||
			lower.contains("semaphore") || lower.contains("pthread") || lower.contains("wait") ||
			lower.contains("kill") || lower.contains("signal")) {
			return "Process/Thread";
		}
		if (lower.contains("str") || lower.contains("printf") || lower.contains("sprint") ||
			lower.contains("sscanf") || lower.contains("wcs") || lower.contains("char")) {
			return "String";
		}
		if (lower.contains("objc_msg") || lower.contains("class_") ||
			lower.contains("sel_") || lower.contains("method_")) {
			return "ObjC Runtime";
		}
		if (lower.contains("registry") || lower.contains("regopen") ||
			lower.contains("regquery") || lower.contains("regset")) {
			return "Registry";
		}
		if (lower.contains("dlopen") || lower.contains("dlsym") ||
			lower.contains("loadlib") || lower.contains("getproc")) {
			return "Dynamic Loading";
		}
		return "Other";
	}

	// -----------------------------------------------------------------------
	// Code Classification
	// -----------------------------------------------------------------------

	private void addCodeClassificationSection() {
		JPanel panel = createSectionPanel("Code Classification");

		FunctionManager funcMgr = program.getFunctionManager();
		int total = funcMgr.getFunctionCount();
		if (total == 0) {
			JLabel empty = new JLabel("  (No functions found)");
			empty.setForeground(Color.GRAY);
			panel.add(empty);
			contentPanel.add(panel);
			return;
		}

		int named = 0;
		int auto = 0;
		int small = 0;   // < 10 instructions
		int medium = 0;  // 10-100
		int large = 0;   // > 100

		FunctionIterator iter = funcMgr.getFunctions(true);
		while (iter.hasNext()) {
			Function func = iter.next();
			if (func.getName().startsWith("FUN_")) {
				auto++;
			}
			else {
				named++;
			}

			long size = func.getBody().getNumAddresses();
			if (size < 20) {
				small++;
			}
			else if (size < 200) {
				medium++;
			}
			else {
				large++;
			}
		}

		// Confidence assessment
		int namedPct = (int) ((named * 100.0) / total);
		String confidence;
		Color confidenceColor;
		if (namedPct > 70) {
			confidence = "HIGH - Well analyzed binary";
			confidenceColor = new Color(76, 175, 80);
		}
		else if (namedPct > 30) {
			confidence = "MEDIUM - Partial analysis";
			confidenceColor = new Color(255, 193, 7);
		}
		else {
			confidence = "LOW - Needs more analysis";
			confidenceColor = new Color(244, 67, 54);
		}

		JLabel confidenceLabel = new JLabel("  Analysis Confidence: " + confidence);
		confidenceLabel.setForeground(confidenceColor);
		confidenceLabel.setFont(confidenceLabel.getFont().deriveFont(Font.BOLD));
		confidenceLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
		panel.add(confidenceLabel);
		panel.add(Box.createVerticalStrut(6));

		addInfoRow(panel, "Named Functions", String.format("%d (%d%%)", named, namedPct));
		addInfoRow(panel, "Auto-generated", String.format("%d (%d%%)", auto,
			(int) ((auto * 100.0) / total)));
		panel.add(Box.createVerticalStrut(4));

		addInfoRow(panel, "Small (<20 bytes)", String.valueOf(small));
		addInfoRow(panel, "Medium (20-200 bytes)", String.valueOf(medium));
		addInfoRow(panel, "Large (>200 bytes)", String.valueOf(large));

		contentPanel.add(panel);
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
			new EmptyBorder(6, 8, 6, 8)));
		panel.setAlignmentX(Component.LEFT_ALIGNMENT);
		panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
		return panel;
	}

	private void addInfoRow(JPanel panel, String label, String value) {
		JPanel row = new JPanel(new BorderLayout());
		row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 20));
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

	// -----------------------------------------------------------------------
	// Data holder
	// -----------------------------------------------------------------------

	private static class StringEntry {
		final Address address;
		final String value;
		final int score;

		StringEntry(Address address, String value, int score) {
			this.address = address;
			this.value = value;
			this.score = score;
		}
	}
}
