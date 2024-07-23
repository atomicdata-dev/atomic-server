import { styled } from 'styled-components';
import { Row } from '../../components/Row';

export function PermissionRow({
  children,
  ...props
}: React.PropsWithChildren<React.HTMLAttributes<HTMLDivElement>>) {
  return (
    <Row {...props} center>
      {children}
    </Row>
  );
}

PermissionRow.TitleColumn = styled.div`
  overflow: hidden;
  flex: 1;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

PermissionRow.ControlsColumn = styled.div`
  flex-basis: 6rem;
  display: flex;
  justify-content: space-around;
`;
