import { Fragment } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { ProgramBadge } from './ProgramBadge';

const programs = [
  {
    id: 'p0',
    title: 'Ihmislähtöinen ja kestävä digitalisaatio',
    subtitle: 'Tietopoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p1',
    title: 'Kohti kestävämpää ja reilumpaa maataloutta',
    subtitle: 'Maatalouspoliittinen ohjelma',
    status: 'green'
  },
];
const testPrograms = [
  {
    id: 'px_luo',
    title: 'Lorem ipsum dolor sit amet',
    subtitle: 'Ohjelmaluonnos (ei hyväksytty)',
    status: 'gray'
  },
  {
    id: 'px_hyv',
    title: 'Lorem ipsum dolor sit amet',
    subtitle: 'Hyväksytty ohjelma',
    status: 'green'
  },
  {
    id: 'px_van',
    title: 'Lorem ipsum dolor sit amet',
    subtitle: 'Vanhentunut ohjelma',
    status: 'yellow'
  },
  {
    id: 'px_poi',
    title: 'Lorem ipsum dolor sit amet',
    subtitle: 'Poistunut ohjelma',
    status: 'red'
  },
];

export default function SideBar() {
  return (
    <div className='sidebar-container'>
      <div className='sidebar'>
        <NavLink to='/' end>
          <h1>Ohjelmat</h1>
        </NavLink>
        <p>
          {programs.map(
            program =>
              <ProgramBadge
                id={program.id}
                title={program.title}
                subtitle={program.subtitle}
                status={program.status}
              />)}
        </p>
        <h2>Testiohjelmat</h2>
        <p>
          {testPrograms.map(
            program =>
              <ProgramBadge
                id={program.id}
                title={program.title}
                subtitle={program.subtitle}
                status={program.status}
              />)}
        </p>
      </div>
      <div className='content'>
        <Outlet />
      </div>
    </div>
  );
}