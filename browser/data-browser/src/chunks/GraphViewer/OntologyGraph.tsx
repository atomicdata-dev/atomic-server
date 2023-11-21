import { Resource, useStore } from '@tomic/react';
import { useCallback } from 'react';
import ReactFlow, {
  Controls,
  useReactFlow,
  Node,
  ReactFlowProvider,
} from 'reactflow';
import 'reactflow/dist/style.css';
import './reactFlowOverrides.css';
import { buildGraph } from './buildGraph';
import { FloatingEdge } from './FloatingEdge';
import { useGraph } from './useGraph';
import { useEffectOnce } from '../../hooks/useEffectOnce';
import { toAnchorId } from '../../views/OntologyPage/toAnchorId';

const edgeTypes = {
  floating: FloatingEdge,
};

interface OntologyGraphProps {
  ontology: Resource;
}

/**
 * !ASYNC COMPONENT, DO NOT IMPORT DIRECTLY!
 * Displays an ontology as a graph.
 */
export default function OntologyGraph({
  ...props
}: OntologyGraphProps): JSX.Element {
  return (
    <ReactFlowProvider>
      <OntologyGraphInner {...props} />
    </ReactFlowProvider>
  );
}

function OntologyGraphInner({ ontology }: OntologyGraphProps): JSX.Element {
  const store = useStore();
  const { fitView } = useReactFlow();

  const { nodes, edges, setGraph, handleNodeChange, handleNodeDoubleClick } =
    useGraph(ontology);

  useEffectOnce(() => {
    buildGraph(ontology, store).then(([n, e]) => {
      setGraph(n, e);

      requestAnimationFrame(() => {
        fitView();
      });
    });
  });

  const handleClick = useCallback((_: React.MouseEvent, node: Node) => {
    const domId = toAnchorId(node.id);

    document.getElementById(domId)?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  return (
    <ReactFlow
      fitView
      nodes={nodes}
      edges={edges}
      edgeTypes={edgeTypes}
      onNodesChange={handleNodeChange}
      onNodeClick={handleClick}
      onNodeDoubleClick={handleNodeDoubleClick}
    >
      <Controls position='top-left' showInteractive={false} />
    </ReactFlow>
  );
}
