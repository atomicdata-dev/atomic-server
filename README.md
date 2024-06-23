Tämä ohjelmisto pohjautuu avoimen lähdekoodin projektiin [Atomic Server](https://atomicserver.eu/). Dokumentaatio löytyy [täältä](https://docs.atomicdata.dev).

## Kehitysympäristön pystytys

1. Asenna [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html).
2. Asenna [Node.js](https://nodejs.org/en/download/package-manager) ja [pnpm](https://pnpm.io/installation).
3. Kloonaa tämä repositorio.
4. Käynnistä atomic server ajamalla projektin juuressa
   ```sh
   cargo run
   ```
   Ensimmäisen käynnistyksen jälkeen voit käynnistää palvelimen myös komennolla
   ```sh
   ./target/debug/atomic-server
   ```
5. Avaa toinen ikkuna ja käynnistä atomic browser:
   ```sh
   cd browser
   pnpm install
   pnpm start
   ```
6. Sivu pyörii nyt paikallisesti osoitteessa http://localhost:5173. Tekemäsi muutokset React-koodiin päivityvät sivulle automaattisesti.
7. Luo itsellesi käyttäjä seuraamalla dokumentaation [ohjeita](https://docs.atomicdata.dev/atomicserver/gui).
