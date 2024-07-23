import { Button } from '../components/Button';
import { ContainerFull } from '../components/Containers';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  useDialog,
} from '../components/Dialog';

export function Sandbox(): JSX.Element {
  const { dialogProps, show, isOpen } = useDialog();

  return (
    <main>
      <ContainerFull>
        <h1>Sandbox</h1>
        <p>
          Welcome to the sandbox. This is a place to test components in
          isolation.
        </p>
        <p>{isOpen ? 'TRUE' : 'FALSE'}</p>
        <Button onClick={show}>Button</Button>
        <Dialog {...dialogProps}>
          <DialogTitle>Title</DialogTitle>
          <DialogContent>Content</DialogContent>
        </Dialog>
      </ContainerFull>
    </main>
  );
}
