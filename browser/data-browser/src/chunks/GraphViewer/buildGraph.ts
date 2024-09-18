import { core, Datatype, Resource, Store } from '@tomic/react';
import { Node, Edge, MarkerType } from 'reactflow';
import { randomString } from '../../helpers/randomString';
import { DefaultTheme } from 'styled-components';

const RELEVANT_DATATYPES = [Datatype.ATOMIC_URL, Datatype.RESOURCEARRAY];

export interface NodeData {
  label: string;
  external: boolean;
}

export enum OverlapIndex {
  First,
  Second,
}

export interface EdgeData {
  required: boolean;
  overlapping: boolean;
}

interface Routing {
  source: string;
  target: string;
}

const label = (text: string, required: boolean): string =>
  `${required ? '*' : ''}${text}`;

const newEdge = (
  routing: Routing,
  name: string,
  required: boolean,
  overlapping: boolean,
): Edge<EdgeData> => ({
  ...routing,
  id: randomString(),
  label: label(name, required),
  markerEnd: {
    type: MarkerType.ArrowClosed,
    width: 15,
    height: 15,
  },
  type: 'floating',
  data: { required, overlapping },
});

const findEdgeWithSameRouting = (edges: Edge[], routing: Routing): number =>
  edges.findIndex(
    edge => edge.source === routing.source && edge.target === routing.target,
  );

const findAndTagOverlappingEdges = (
  edges: Edge[],
  routing: Routing,
): boolean => {
  const index = edges.findIndex(
    edge => edge.target === routing.source && edge.source === routing.target,
  );

  if (index !== -1) {
    edges[index] = {
      ...edges[index],
      data: {
        ...edges[index].data,
        overlapping: true,
      },
    };
  }

  return index !== -1;
};

const mergeEdges = (
  existingEdge: Edge<EdgeData>,
  name: string,
  isRequired: boolean,
): Edge<EdgeData> => ({
  ...existingEdge,
  data: {
    required: isRequired || (existingEdge.data?.required ?? false),
    overlapping: existingEdge.data?.overlapping ?? false,
  },
  label: `${existingEdge.label},\n${label(name, isRequired)}`,
});

export async function buildGraph(
  ontology: Resource,
  store: Store,
): Promise<[Node<NodeData>[], Edge<EdgeData>[]]> {
  const classes = ontology.get(core.properties.classes);
  // Any classes that are not in the ontology but are referenced by classes that are in the ontology.
  const externalClasses: Set<string> = new Set();

  const nodes: Node[] = [];
  const edges: Edge[] = [];

  const classToNode = async (
    classSubject: string,
    isExtra = false,
  ): Promise<Node<NodeData>> => {
    const res = await store.getResource(classSubject);

    if (!isExtra) {
      await createEdges(res);
    }

    return {
      id: classSubject,
      position: { x: 0, y: 100 },
      width: 100,
      height: 100,
      data: { label: res.title, external: isExtra },
    };
  };

  const createEdges = async (classResource: Resource) => {
    const recommends = (classResource.get(core.properties.recommends) ??
      []) as string[];
    const requires = (classResource.get(core.properties.requires) ??
      []) as string[];

    for (const subject of [...recommends, ...requires]) {
      const property = await store.getProperty(subject);

      const isRequired = requires.includes(subject);

      if (
        RELEVANT_DATATYPES.includes(property.datatype) &&
        property.classType
      ) {
        const routing = {
          source: classResource.subject,
          target: property.classType,
        };

        const existingEdgeIndex = findEdgeWithSameRouting(edges, routing);

        if (existingEdgeIndex === -1) {
          const isOverlapping = findAndTagOverlappingEdges(edges, routing);

          edges.push(
            newEdge(routing, property.shortname, isRequired, isOverlapping),
          );

          if (!classes.includes(property.classType)) {
            externalClasses.add(property.classType);
          }

          continue;
        }

        edges[existingEdgeIndex] = mergeEdges(
          edges[existingEdgeIndex],
          property.shortname,
          isRequired,
        );
      }
    }
  };

  for (const item of classes) {
    nodes.push(await classToNode(item));
  }

  for (const extra of externalClasses) {
    nodes.push(await classToNode(extra, true));
  }

  return [nodes, edges];
}

export function applyNodeStyling(
  nodes: Node<NodeData>[],
  theme: DefaultTheme,
): Node<NodeData>[] {
  return nodes.map(node => ({
    ...node,
    style: {
      ...node.style,
      backgroundColor: theme.colors.bg,
      borderColor: theme.colors.bg2,
      color: theme.colors.text,
      borderStyle: node.data.external ? 'dashed' : 'solid',
    },
  }));
}
