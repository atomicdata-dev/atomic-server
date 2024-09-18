import {
  Edge,
  Node,
  NodeChange,
  NodePositionChange,
  applyNodeChanges,
} from 'reactflow';
import { EdgeData, NodeData, applyNodeStyling } from './buildGraph';
import { useCallback, useMemo, useState } from 'react';
import Dagre from '@dagrejs/dagre';
import { useTheme } from 'styled-components';
import { dataBrowser, Resource, useString } from '@tomic/react';

interface CustomNodePositioning {
  [key: string]: [x: number, y: number];
}

type UseNodeReturn = {
  nodes: Node<NodeData>[];
  edges: Edge<EdgeData>[];
  setGraph: (nodes: Node<NodeData>[], edges: Edge<EdgeData>[]) => void;
  handleNodeChange: (changes: NodeChange[]) => void;
  handleNodeDoubleClick: (event: React.MouseEvent, node: Node) => void;
};

const g = new Dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));

const getLayoutedElements = (nodes: Node[], edges: Edge[]) => {
  g.setGraph({ rankdir: 'vertical', ranksep: 70 });

  edges.forEach(edge => g.setEdge(edge.source, edge.target));
  nodes.forEach(node => g.setNode(node.id, { width: 120, height: 100 }));

  Dagre.layout(g);

  return {
    positionedNodes: nodes.map(node => {
      const { x, y } = g.node(node.id);

      return { ...node, position: { x, y } };
    }),
    positionedEdges: edges,
  };
};

const placeNodesInSpace = (
  nodes: Node[],
  edges: Edge[],
  customPositioning: CustomNodePositioning,
): [nodes: Node[], edges: Edge[]] => {
  const { positionedNodes, positionedEdges } = getLayoutedElements(
    nodes,
    edges,
  );

  const ajustedNodes = positionedNodes.map(node => {
    if (customPositioning[node.id]) {
      const [x, y] = customPositioning[node.id];

      return { ...node, position: { x, y }, positionAbsolute: { x, y } };
    }

    return node;
  });

  return [ajustedNodes, positionedEdges];
};

export function useGraph(ontology: Resource): UseNodeReturn {
  const theme = useTheme();

  const [customPositioningSTR, setCustomPositioningSTR] = useString(
    ontology,
    dataBrowser.properties.customNodePositioning,
    { commit: true },
  );

  const customPositioning = useMemo(
    () => JSON.parse(customPositioningSTR || '{}'),
    [customPositioningSTR],
  );

  const [nodes, setNodes] = useState<Node<NodeData>[]>([]);
  const [edges, setEdges] = useState<Edge<EdgeData>[]>([]);
  const [lastPositionChange, setLastPositionChange] =
    useState<NodePositionChange>();

  const setGraph = useCallback(
    (_nodes: Node<NodeData>[], _edges: Edge<EdgeData>[]) => {
      const [positionedNodes, positionedEdges] = placeNodesInSpace(
        _nodes,
        _edges,
        customPositioning,
      );
      setNodes(applyNodeStyling(positionedNodes, theme));
      setEdges(positionedEdges);
    },
    [theme, customPositioning],
  );

  const handleNodeDoubleClick = useCallback(
    async (_e: React.MouseEvent, node: Node) => {
      const newCustomPositioning = {
        ...customPositioning,
      };

      delete newCustomPositioning[node.id];

      await setCustomPositioningSTR(JSON.stringify(newCustomPositioning));

      const [positionedNodes] = placeNodesInSpace(
        nodes,
        edges,
        newCustomPositioning,
      );

      setNodes(positionedNodes);
    },
    [customPositioning, nodes, edges],
  );

  const handleNodeChange = useCallback(
    (changes: NodeChange[]) => {
      const change = changes[0];

      if (change.type === 'position') {
        if (change.dragging) {
          setLastPositionChange(change);
        } else {
          setCustomPositioningSTR(
            JSON.stringify({
              ...customPositioning,
              [change.id]: [
                lastPositionChange!.positionAbsolute?.x,
                lastPositionChange!.positionAbsolute?.y,
              ],
            }),
          );
        }
      }

      setNodes(prev => applyNodeChanges(changes, prev));
    },
    [customPositioning, lastPositionChange],
  );

  return {
    nodes,
    edges,
    setGraph,
    handleNodeChange,
    handleNodeDoubleClick,
  };
}
