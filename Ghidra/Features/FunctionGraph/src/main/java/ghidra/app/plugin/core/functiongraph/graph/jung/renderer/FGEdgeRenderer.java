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
package ghidra.app.plugin.core.functiongraph.graph.jung.renderer;

import java.awt.*;

import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.graph.viewer.renderer.ArticulatedEdgeRenderer;
import ghidra.program.model.symbol.FlowType;

/**
 * Enhanced renderer for Function Graph edges. Provides:
 * <ul>
 * <li>Flow-type-based coloring (fallthrough, conditional, unconditional)</li>
 * <li>Dashed strokes for conditional branches for visual differentiation</li>
 * <li>Thicker strokes for unconditional jumps</li>
 * <li>Smooth round caps and joins for cleaner appearance</li>
 * </ul>
 */
public class FGEdgeRenderer extends ArticulatedEdgeRenderer<FGVertex, FGEdge> {

	// Stroke styles for different edge types
	private static final BasicStroke FALLTHROUGH_STROKE =
		new BasicStroke(1.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND);
	private static final BasicStroke UNCONDITIONAL_STROKE =
		new BasicStroke(2.0f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND);
	private static final BasicStroke CONDITIONAL_STROKE =
		new BasicStroke(1.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND,
			10.0f, new float[] { 8.0f, 4.0f }, 0.0f);

	@Override
	public Color getDrawColor(Graph<FGVertex, FGEdge> g, FGEdge e) {
		FunctionGraphOptions options = getOptions(g);
		return options.getColor(e.getFlowType());
	}

	@Override
	public Color getFocusedColor(Graph<FGVertex, FGEdge> g, FGEdge e) {
		FunctionGraphOptions options = getOptions(g);
		return options.getColor(e.getFlowType());
	}

	@Override
	public Color getSelectedColor(Graph<FGVertex, FGEdge> g, FGEdge e) {
		FunctionGraphOptions options = getOptions(g);
		return options.getHighlightColor(e.getFlowType());
	}

	@Override
	public Color getHoveredColor(Graph<FGVertex, FGEdge> g, FGEdge e) {
		FunctionGraphOptions options = getOptions(g);
		return options.getColor(e.getFlowType());
	}

	/**
	 * Returns a stroke appropriate for the edge's flow type.
	 * Conditional jumps use dashed lines, unconditional use thicker solid lines,
	 * and fallthroughs use standard thin solid lines.
	 * <p>
	 * Overrides the base class hook to provide flow-type-aware stroke rendering.
	 */
	@Override
	protected Stroke getBaseStroke(FGEdge e) {
		FlowType flowType = e.getFlowType();
		if (flowType == null) {
			return FALLTHROUGH_STROKE;
		}

		if (flowType.isConditional()) {
			return CONDITIONAL_STROKE;
		}
		else if (flowType.isUnConditional() && !flowType.isFallthrough()) {
			return UNCONDITIONAL_STROKE;
		}
		return FALLTHROUGH_STROKE;
	}

	private FunctionGraphOptions getOptions(Graph<FGVertex, FGEdge> g) {
		FunctionGraph fg = (FunctionGraph) g;
		return fg.getOptions();
	}
}
