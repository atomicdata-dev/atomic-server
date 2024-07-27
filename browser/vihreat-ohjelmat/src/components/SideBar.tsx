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
  {
    id: 'p2',
    title: 'Talouden avulla tavoitteisiin',
    subtitle: 'Elinkeinopoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p3',
    title: 'Huomisen kestävät ja viihtyisät kaupungit',
    subtitle: 'Vihreiden ohjelma suurille kaupungeille',
    status: 'green'
  },
  {
    id: 'p4',
    title: 'Ei enää toivottomia velkavuoria',
    subtitle: 'Vihreät ratkaisut yksityishenkilöiden ylivelkaantumiseen',
    status: 'green'
  },
  {
    id: 'p5',
    title: 'Oikeuspo­liit­tinen ohjelma',
    subtitle: 'Oikeuspo­liit­tinen ohjelma',
    status: 'green'
  },
  {
    id: 'p6',
    title: 'Tasa-arvo- ja yhdenvertaisuusohjelma',
    subtitle: 'Tasa-arvo- ja yhdenvertaisuusohjelma',
    status: 'green'
  },
  {
    id: 'p7',
    title: 'Ulko- ja turvalli­suus­po­liit­tinen ohjelma',
    subtitle: 'Ulko- ja turvalli­suus­po­liit­tinen ohjelma',
    status: 'green'
  },
  {
    id: 'p8',
    title: 'Tiedepoliittinen ohjelma',
    subtitle: 'Tiedepoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p9',
    title: 'Vihreiden energiavisio 2035',
    subtitle: 'Vihreiden energiavisio 2035',
    status: 'green'
  },
  {
    id: 'p10',
    title: 'Maahanmuuttopoliittinen ohjelma',
    subtitle: 'Maahanmuuttopoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p11',
    title: 'Visio liikenteen tulevaisuudesta',
    subtitle: 'liikennepoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p12',
    title: 'Vihreässä Suomessa ihmisillä on toivoa ympäri maata',
    subtitle: 'Vihreä maaseutu- ja aluepoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p13',
    title: 'Vihreiden poliittinen ohjelma 2023–2027',
    subtitle: 'Vihreiden poliittinen ohjelma 2023–2027',
    status: 'green'
  },
  {
    id: 'p14',
    title: 'Vihreiden vesiensuo­je­luoh­jelma',
    subtitle: 'Vihreiden vesiensuo­je­luoh­jelma',
    status: 'green'
  },
  {
    id: 'p15',
    title: 'Kaikkien sosiaaliturva',
    subtitle: 'Vihreiden sosiaaliturvaohjelma',
    status: 'green'
  },
  {
    id: 'p16',
    title: 'Vihreä kulttuurimanifesti ja kulttuuripoliittinen ohjelma',
    subtitle: 'Kulttuuripoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p17',
    title: 'Vihreiden aluevaaliohjelma',
    subtitle: 'Vihreiden aluevaaliohjelma',
    status: 'green'
  },
  {
    id: 'p18',
    title: 'Vihreä Eurooppa-ohjelma',
    subtitle: 'Vihreä Eurooppa-ohjelma',
    status: 'green'
  },
  {
    id: 'p19',
    title: 'Koulutusta, kannustavuutta ja turvaa',
    subtitle: 'Vihreiden työllisyyspoliittiset linjaukset',
    status: 'green'
  },
  {
    id: 'p20',
    title: 'Lapsi- ja nuorisopoliittinen ohjelma',
    subtitle: 'Lapsi- ja nuorisopoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p21',
    title: 'Metsäpoliittinen ohjelma',
    subtitle: 'Metsäpoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p22',
    title: 'Kunta- ja kaupunkivisio',
    subtitle: 'Kunta- ja kaupunkivisio',
    status: 'green'
  },
  {
    id: 'p23',
    title: 'Ikääntymispoliittinen ohjelma',
    subtitle: 'Ikääntymispoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p24',
    title: 'Vihreät muuttavat maailmaa, jotta elämä maapallolla voi kukoistaa',
    subtitle: 'Vihreiden periaateohjelma 2020-2028',
    status: 'green'
  },
  {
    id: 'p25',
    title: 'Miten päästöjä ja köyhyyttä vähennetään samaan aikaan?',
    subtitle: 'Reilun vihreän muutoksen ohjelma',
    status: 'green'
  },
  {
    id: 'p26',
    title: 'Rakennetaan uutta, luodaan toivoa, suojellaan arvokkainta',
    subtitle: 'Eurovaaliohjelma 2024',
    status: 'green'
  },
  {
    id: 'p27',
    title: 'Suojele elämää',
    subtitle: 'Eduskuntavaaliohjelma 2023',
    status: 'green'
  },
  {
    id: 'p28',
    title: 'Vihreiden Lukeva Suomi -teesit',
    subtitle: 'Vihreiden Lukeva Suomi -teesit',
    status: 'green'
  },
  {
    id: 'p29',
    title: 'Pelastetaan maailman paras koulutus',
    subtitle: 'koulutuspoliittinen ohjelma',
    status: 'green'
  },
  {
    id: 'p30',
    title: 'Luonto vastuullamme',
    subtitle: 'Vihreiden luonnonsuojeluohjelma',
    status: 'green'
  },
  {
    id: 'p31',
    title: 'Kulttuuripoliittinen ohjelma',
    subtitle: 'Kulttuuripoliittinen ohjelma',
    status: 'red'
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