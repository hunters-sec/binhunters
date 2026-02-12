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

import java.awt.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;
import javax.swing.tree.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.builder.ActionBuilder;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;

/**
 * Provides a dockable documentation panel with a tree-based navigation sidebar,
 * search bar, and HTML content viewer. Documentation covers all major Binhunters
 * features and workflows.
 */
public class DocumentationProvider extends ComponentProvider {

	private JPanel mainPanel;
	private JTree topicTree;
	private JEditorPane contentPane;
	private JTextField searchField;
	private DefaultTreeModel treeModel;
	private DefaultMutableTreeNode rootNode;
	private Map<String, String> documentationMap;
	private Map<String, DefaultMutableTreeNode> nodeMap;

	public DocumentationProvider(Plugin plugin) {
		super(plugin.getTool(), "Documentation", plugin.getName());
		setTitle("Binhunters Documentation");
		setIcon(null);
		setHelpLocation(new HelpLocation("Documentation", "Overview"));
		setDefaultWindowPosition(docking.WindowPosition.RIGHT);
		setVisible(false);

		documentationMap = DocumentationContent.getAllDocumentation();
		nodeMap = new HashMap<>();

		buildPanel();
		createActions(plugin);
	}

	private void buildPanel() {
		mainPanel = new JPanel(new BorderLayout());

		// --- Search bar at top ---
		searchField = new JTextField();
		searchField.putClientProperty("JTextField.placeholderText", "Search documentation...");
		searchField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				filterTree();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				filterTree();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				filterTree();
			}
		});

		JPanel searchPanel = new JPanel(new BorderLayout(4, 0));
		searchPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
		searchPanel.add(new JLabel("Search: "), BorderLayout.WEST);
		searchPanel.add(searchField, BorderLayout.CENTER);
		mainPanel.add(searchPanel, BorderLayout.NORTH);

		// --- Build tree ---
		rootNode = buildTreeNodes();
		treeModel = new DefaultTreeModel(rootNode);
		topicTree = new JTree(treeModel);
		topicTree.setRootVisible(false);
		topicTree.setShowsRootHandles(true);
		topicTree.getSelectionModel().setSelectionMode(
			TreeSelectionModel.SINGLE_TREE_SELECTION);

		topicTree.addTreeSelectionListener(e -> {
			DefaultMutableTreeNode node =
				(DefaultMutableTreeNode) topicTree.getLastSelectedPathComponent();
			if (node == null) {
				return;
			}
			String key = getNodeKey(node);
			if (key != null && documentationMap.containsKey(key)) {
				showContent(documentationMap.get(key));
			}
		});

		// Expand first two levels
		for (int i = 0; i < topicTree.getRowCount(); i++) {
			topicTree.expandRow(i);
		}

		JScrollPane treeScroll = new JScrollPane(topicTree);
		treeScroll.setPreferredSize(new Dimension(220, 400));

		// --- Content pane ---
		contentPane = new JEditorPane();
		contentPane.setEditable(false);
		contentPane.setContentType("text/html");

		HTMLEditorKit kit = new HTMLEditorKit();
		StyleSheet styleSheet = kit.getStyleSheet();
		styleSheet.addRule("body { font-family: sans-serif; font-size: 12px; margin: 10px; }");
		styleSheet.addRule("h1 { color: #2c3e50; font-size: 18px; border-bottom: 2px solid #3498db; padding-bottom: 4px; }");
		styleSheet.addRule("h2 { color: #2980b9; font-size: 15px; margin-top: 14px; }");
		styleSheet.addRule("h3 { color: #27ae60; font-size: 13px; }");
		styleSheet.addRule("code { background: #f0f0f0; padding: 1px 4px; font-family: monospace; font-size: 11px; }");
		styleSheet.addRule("pre { background: #f8f8f8; border: 1px solid #ddd; padding: 8px; font-family: monospace; font-size: 11px; overflow-x: auto; }");
		styleSheet.addRule("table { border-collapse: collapse; width: 100%; margin: 8px 0; }");
		styleSheet.addRule("th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; }");
		styleSheet.addRule("th { background: #f0f0f0; font-weight: bold; }");
		styleSheet.addRule("ul, ol { margin-left: 20px; }");
		styleSheet.addRule("li { margin-bottom: 4px; }");
		styleSheet.addRule(".tip { background: #eaf6ff; border-left: 4px solid #3498db; padding: 8px; margin: 8px 0; }");
		styleSheet.addRule(".warning { background: #fff3cd; border-left: 4px solid #f39c12; padding: 8px; margin: 8px 0; }");
		contentPane.setEditorKit(kit);

		// Show welcome content
		showContent(DocumentationContent.getWelcome());

		JScrollPane contentScroll = new JScrollPane(contentPane);

		// --- Split pane ---
		JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
			treeScroll, contentScroll);
		splitPane.setDividerLocation(220);
		splitPane.setOneTouchExpandable(true);
		mainPanel.add(splitPane, BorderLayout.CENTER);
	}

	private DefaultMutableTreeNode buildTreeNodes() {
		DefaultMutableTreeNode root = new DefaultMutableTreeNode("Documentation");

		addCategory(root, "Getting Started", new String[] {
			"Overview", "Basic Workflow", "Keyboard Shortcuts"
		});
		addCategory(root, "Program Tree", new String[] {
			"Overview", "Memory Sections", "Fragments"
		});
		addCategory(root, "Symbols", new String[] {
			"Overview", "Imports", "Exports", "Functions", "Labels", "Classes", "Namespaces"
		});
		addCategory(root, "Data Types", new String[] {
			"Overview", "Built-in Types", "Structures", "Enums", "Creating Types"
		});
		addCategory(root, "Functions", new String[] {
			"Overview", "Function List", "Signatures", "Calling Conventions", "Stack Frames"
		});
		addCategory(root, "Decompiler", new String[] {
			"Overview", "Reading Output", "Navigation", "Export"
		});
		addCategory(root, "Graphs", new String[] {
			"Overview", "Function Graph", "Block Flow Graph", "Code Flow Graph",
			"Call Graph", "Data Flow"
		});
		addCategory(root, "Scripting", new String[] {
			"Overview", "Interactive Console", "Writing Scripts",
			"API Reference", "Common Workflows"
		});
		addCategory(root, "Analysis", new String[] {
			"Overview", "Auto Analysis", "One-Shot Analyzers", "Options"
		});
		addCategory(root, "Navigation", new String[] {
			"Overview", "Search", "Bookmarks", "Cross References"
		});
		addCategory(root, "Binhunters Features", new String[] {
			"Triage Panel", "Context Sidebar", "Bulk Export",
			"Enhanced Graphs", "Improved Decompiler"
		});
		addCategory(root, "Tips", new String[] {
			"All Tips"
		});

		return root;
	}

	private void addCategory(DefaultMutableTreeNode parent, String category, String[] topics) {
		DefaultMutableTreeNode categoryNode = new DefaultMutableTreeNode(category);
		nodeMap.put(category, categoryNode);
		parent.add(categoryNode);

		for (String topic : topics) {
			DefaultMutableTreeNode topicNode = new DefaultMutableTreeNode(topic);
			String key = category + "/" + topic;
			nodeMap.put(key, topicNode);
			categoryNode.add(topicNode);
		}
	}

	private String getNodeKey(DefaultMutableTreeNode node) {
		TreeNode parent = node.getParent();
		if (parent != null && parent != rootNode) {
			return parent.toString() + "/" + node.toString();
		}
		return node.toString();
	}

	private void showContent(String html) {
		contentPane.setText(html);
		contentPane.setCaretPosition(0);
	}

	private void filterTree() {
		String filter = searchField.getText().trim().toLowerCase();
		rootNode.removeAllChildren();

		if (filter.isEmpty()) {
			// Rebuild full tree
			DefaultMutableTreeNode fullRoot = buildTreeNodes();
			for (int i = 0; i < fullRoot.getChildCount(); i++) {
				rootNode.add((DefaultMutableTreeNode) fullRoot.getChildAt(i));
			}
		}
		else {
			// Filter: show only topics containing the search text
			DefaultMutableTreeNode fullRoot = buildTreeNodes();
			for (int i = 0; i < fullRoot.getChildCount(); i++) {
				DefaultMutableTreeNode category =
					(DefaultMutableTreeNode) fullRoot.getChildAt(i);
				DefaultMutableTreeNode filteredCategory = null;

				// Check category name
				boolean categoryMatch = category.toString().toLowerCase().contains(filter);

				for (int j = 0; j < category.getChildCount(); j++) {
					DefaultMutableTreeNode topic =
						(DefaultMutableTreeNode) category.getChildAt(j);
					String key = category.toString() + "/" + topic.toString();
					String content = documentationMap.getOrDefault(key, "");

					if (categoryMatch ||
						topic.toString().toLowerCase().contains(filter) ||
						content.toLowerCase().contains(filter)) {
						if (filteredCategory == null) {
							filteredCategory =
								new DefaultMutableTreeNode(category.toString());
						}
						filteredCategory.add(
							new DefaultMutableTreeNode(topic.toString()));
					}
				}

				if (filteredCategory != null) {
					rootNode.add(filteredCategory);
				}
			}

			// Show search results summary
			int count = 0;
			for (int i = 0; i < rootNode.getChildCount(); i++) {
				count += ((DefaultMutableTreeNode) rootNode.getChildAt(i)).getChildCount();
			}
			showContent("<html><body><h1>Search Results</h1>" +
				"<p>Found <b>" + count + "</b> topics matching '<i>" +
				htmlEscape(filter) + "</i>'. Select a topic from the tree.</p></body></html>");
		}

		treeModel.reload();

		// Expand all after filter
		for (int i = 0; i < topicTree.getRowCount(); i++) {
			topicTree.expandRow(i);
		}
	}

	private void createActions(Plugin plugin) {
		// Main "Documentation" menu action
		new ActionBuilder("Open Documentation", plugin.getName())
			.menuPath("&Documentation", "Open Documentation")
			.menuGroup("A_DOCS", "1")
			.onAction(c -> {
				setVisible(true);
				toFront();
			})
			.buildAndInstall(dockingTool);

		// Quick-access menu items for major sections
		String[] quickSections = {
			"Getting Started", "Program Tree", "Symbols", "Data Types",
			"Functions", "Decompiler", "Graphs", "Scripting", "Analysis"
		};

		int order = 2;
		for (String section : quickSections) {
			final String sectionName = section;
			new ActionBuilder("Docs: " + section, plugin.getName())
				.menuPath("&Documentation", sectionName)
				.menuGroup("B_SECTIONS", String.valueOf(order++))
				.onAction(c -> {
					setVisible(true);
					toFront();
					selectSection(sectionName);
				})
				.buildAndInstall(dockingTool);
		}

		// Search action
		new ActionBuilder("Search Documentation", plugin.getName())
			.menuPath("&Documentation", "Search Documentation...")
			.menuGroup("C_SEARCH", "1")
			.onAction(c -> {
				setVisible(true);
				toFront();
				searchField.requestFocusInWindow();
				searchField.selectAll();
			})
			.buildAndInstall(dockingTool);
	}

	private void selectSection(String sectionName) {
		DefaultMutableTreeNode node = nodeMap.get(sectionName);
		if (node != null) {
			TreePath path = new TreePath(node.getPath());
			topicTree.setSelectionPath(path);
			topicTree.scrollPathToVisible(path);
		}

		// Also show the section overview content
		String key = sectionName + "/Overview";
		if (documentationMap.containsKey(key)) {
			showContent(documentationMap.get(key));
		}
		else if (documentationMap.containsKey(sectionName)) {
			showContent(documentationMap.get(sectionName));
		}
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void dispose() {
		// nothing to dispose
	}

	private static String htmlEscape(String text) {
		return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
	}
}
