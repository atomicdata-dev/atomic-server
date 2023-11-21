import { useChildren } from '@tomic/react';
import { useState } from 'react';

import { FaCaretDown, FaCaretRight } from 'react-icons/fa';
import { ResourceInline } from '../views/ResourceInline';
import { Button } from './Button';
import { Card, CardInsideFull, CardRow } from './Card';

export function Childrenlist({ resource }) {
  const [show, setShow] = useState(false);

  return (
    <>
      <Button onClick={() => setShow(!show)}>
        {show ? <FaCaretDown /> : <FaCaretRight />}
        {' children'}
      </Button>
      {show && <ChildrenList resource={resource} />}
    </>
  );
}

function ChildrenList({ resource }) {
  const children = useChildren(resource);

  return (
    <Card>
      <CardInsideFull>
        {children.map(s => (
          <CardRow key={s}>
            <ResourceInline subject={s} />
          </CardRow>
        ))}
      </CardInsideFull>
    </Card>
  );
}
