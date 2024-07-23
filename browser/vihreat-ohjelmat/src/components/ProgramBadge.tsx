import { NavLink } from "react-router-dom";

interface ProgramBadgeProps {
  id: string;
  title: string;
  subtitle: string;
  status: string;
};

export function ProgramBadge({ id, title, subtitle, status }: ProgramBadgeProps): JSX.Element {
  return (
    <>
      <NavLink
        key={id}
        to={`/ohjelmat/${id}`}
        className={linkStyling}
      >
        <p className={`vo-programbadge vo-programbadge-${status}`}>
          <p className='vo-programbadge-subtitle'>{subtitle}</p>
          <p className='vo-programbadge-title' title={title}>{title}</p>
        </p>
      </NavLink >
    </>
  );
}

export default ProgramBadge;

function linkStyling({ isActive }: { isActive: boolean }) {
  return isActive ? 'vo-selected-program-link' : '';
}