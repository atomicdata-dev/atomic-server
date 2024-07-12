Tämä ohjelmisto pohjautuu avoimen lähdekoodin projektiin [Atomic Server](https://atomicserver.eu/). Dokumentaatio löytyy [täältä](https://docs.atomicdata.dev).

## Kehitysympäristön pystytys

1. Asenna [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html).
2. Asenna [Node.js](https://nodejs.org/en/download/package-manager) ja [pnpm](https://pnpm.io/installation).
3. Kloonaa tämä repositorio.
4. Lisää ohjelmadataa tietokantaan komennolla:
   ```sh
   vihreat-data/init.sh
   ```
5. Käynnistä atomic server ajamalla projektin juuressa
   ```sh
   cargo run
   ```
   Ensimmäisen käynnistyksen jälkeen voit käynnistää palvelimen myös komennolla
   ```sh
   ./target/debug/atomic-server
   ```
6. Avaa toinen ikkuna ja käynnistä atomic browser (admin-näkymä):
   ```sh
   cd browser
   pnpm install
   cd data-browser
   pnpm start
   ```
   Sivu pyörii osoitteessa http://localhost:5173.
7. Luo itsellesi käyttäjä seuraamalla dokumentaation [ohjeita](https://docs.atomicdata.dev/atomicserver/gui).

## Kehittäminen

Ohjelma-alusta on toteutettu laajentamalla Atomic Serverin selainpakettia `browser`.  Laajennuskoodi sijaitsee pääosin uusissa paketeissa `browser/vihreat-ohjelmat` ja `browser/vihreat-lib` sekä kansiossa `browser/data-browser/vihreat`.  Lisäksi kansio `vihreat-data` sisältää työkaluja datan generointiin.

### `vihreat-data`

Sisältää ontologian (datamallin) määrittelyn sekä työkalun `generate-ld`, jolla ontologia ja muu testidata generoidaan Atomic Serverin ymmärtämään JSON-AD -muotoon. Skripti `vihreat-data/init.sh` alustaa tietokannan ontologialla ja testisisällöllä (olemassa oleva tietokanta tuhoutuu!)

### `browser/vihreat-ohjelmat`

Sisältää ohjelma-alustan asiakassivun. Sivulla voi kuka tahansa (tulevaisuudessa) hakea ja tarkastella ohjelmia. Käynnistä sivu ajamalla:

```sh
cd browser/vihreat-ohjelmat
pnpm start
```

Sivu pyörii osoitteessa http://localhost:5175/. Atomic Serverin tulee olla myös käynnissä.

### `browser/vihreat-lib`

Sisältää ohjelma-alustan [ontologian TypeScript-tyypit](https://docs.atomicdata.dev/js-cli) ja yhteisiä React-komponentteja. Asiakas- ja admin-sivuille yhteinen koodi löytyy täältä (esim. ohjelmanäkymä). Jos teet muutoksia pakettiin, aja paketin juuressa `pnpm run build` päivittääksesi muutokset.

### `browser/data-browser/vihreat`

Sisältää täydennyksiä Atomic Serverin admin-sivuun/tekstieditoriin (Atomic Browser). Atomic Server tarjoaa kohtuullisen hyvän tekstieditorin,
mutta sitä jatkokehitetään ohjelma-alustan tarpeisiin. Pyritään eristämään kaikki ohjelma-alustaan liittyvä Atomic Browser-koodi tähän pakettiin, jotta tulee mahdollisimman vähän merge-konflikteja Atomic Serverin kanssa. Käynnistä sivu ajamalla:

```sh
cd browser/data-browser
pnpm start
```

Sivu pyörii osoitteessa http://localhost:5173/. Atomic Serverin tulee olla myös käynnissä.