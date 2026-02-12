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
package functioncalls.graph;

import ghidra.graph.viewer.edge.AbstractVisualEdge;

/**
 * A {@link FunctionCallGraph} edge.
 * Optionally tracks call count for multi-call edges.
 */
public class FcgEdge extends AbstractVisualEdge<FcgVertex> {

	private int callCount = 1;

	public FcgEdge(FcgVertex start, FcgVertex end) {
		super(start, end);
	}

	@SuppressWarnings("unchecked")
	// Suppressing warning on the return type; we know our class is the right type
	@Override
	public FcgEdge cloneEdge(FcgVertex start, FcgVertex end) {
		FcgEdge clone = new FcgEdge(start, end);
		clone.callCount = this.callCount;
		return clone;
	}

	/**
	 * Returns the number of call references from the start function to the end function.
	 * A value of 1 means a single call site; values > 1 indicate multiple call sites.
	 * @return the call count
	 */
	public int getCallCount() {
		return callCount;
	}

	/**
	 * Sets the number of call references between the connected functions.
	 * @param count the call count
	 */
	public void setCallCount(int count) {
		this.callCount = count;
	}

	/**
	 * Returns true if this edge is a direct edge from a lower level.  Any other edges are 
	 * considered indirect and are less important in the graph.
	 * 
	 * @return true if this edge is a direct edge from a lower level
	 */
	public boolean isDirectEdge() {
		FcgLevel startLevel = getStart().getLevel();
		FcgLevel endLevel = getEnd().getLevel();
		if (startLevel.isSource() || endLevel.isSource()) {
			// all info leaving the source is important/'direct'
			return true;
		}

		FcgLevel parent = startLevel.parent();
		if (parent.equals(endLevel)) {
			return true;
		}

		FcgLevel child = startLevel.child();
		return child.equals(endLevel);
	}
}
