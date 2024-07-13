export function ViewIndex(): JSX.Element {
  return (
    <div className='vo-container'>
      <h1>Ohjelmat</h1>
      <p><a href="/ohjelmat/p0">Tietopoliittinen ohjelma</a></p>
      <h2>Testiohjelmat</h2>
      <p>
        <a href="/ohjelmat/px_luo">Ohjelmaluonnos (ei hyväksytty)</a>
        <br />
        <a href="/ohjelmat/px_hyv">Hyväksytty ohjelma</a>
        <br />
        <a href="/ohjelmat/px_van">Vanhentunut ohjelma</a>
        <br />
        <a href="/ohjelmat/px_poi">Poistunut ohjelma</a>
      </p>
    </div>
  );
}

export default ViewIndex;
