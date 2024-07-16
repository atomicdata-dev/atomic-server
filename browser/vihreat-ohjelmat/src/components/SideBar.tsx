import { Fragment } from 'react';
import { NavLink, Outlet } from 'react-router-dom';

const programs = [
  { id: 'p0', title: 'Tietopoliittinen ohjelma' },
  { id: 'p1', title: 'Maatalouspoliittinen ohjelma' },
];
const testPrograms = [
  { id: 'px_luo', title: 'Ohjelmaluonnos (ei hyväksytty)' },
  { id: 'px_hyv', title: 'Hyväksytty ohjelma' },
  { id: 'px_van', title: 'Vanhentunut ohjelma' },
  { id: 'px_poi', title: 'Poistunut ohjelma' },
];

export default function SideBar() {
  return (
    <div className='sidebar-container'>
      <div className='sidebar'>
        <NavLink to='/' end>
          <h1>Ohjelmat</h1>
        </NavLink>
        <p>
          {programs.map(program => (
            <Fragment key={program.id}>
              <NavLink
                key={program.id}
                to={`/ohjelmat/${program.id}`}
                className={linkStyling}
              >
                {program.title}
              </NavLink>
              <br />
            </Fragment>
          ))}
        </p>
        <h2>Testiohjelmat</h2>
        <p>
          {testPrograms.map(program => (
            <Fragment key={program.id}>
              <NavLink to={`/ohjelmat/${program.id}`} className={linkStyling}>
                {program.title}
              </NavLink>
              <br />
            </Fragment>
          ))}
        </p>
      </div>
      <div className='content'>
        <Outlet />
      </div>
    </div>
  );
}

function linkStyling({ isActive }: { isActive: boolean }) {
  return isActive ? 'selected-program' : '';
}
