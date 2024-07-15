from generate_ld import url


def build() -> list[dict]:
    return [
        _build_ontology(),
        _build_Program(),
        _build_Title(),
        _build_Paragraph(),
        _build_ActionItem(),
        _build_title(),
        _build_subtitle(),
        _build_elements(),
        _build_approvedOn(),
        _build_updatedOn(),
        _build_retiredOn(),
        _build_staleOn(),
        _build_text(),
        _build_titleLevel(),
    ]


def _build_ontology() -> dict:
    return {
        "@id": url.local("o"),
        url.atomic("properties/parent"): url.local(),
        url.atomic("properties/shortname"): "ontology",
        url.atomic("properties/description"): _markdown(
            """
            Vihreiden ohjelma-alustan ontologia.
            """
        ),
        url.atomic("properties/isA"): [url.atomic("class/ontology")],
        url.atomic("properties/classes"): [
            url.local("o/Program"),
            url.local("o/Title"),
            url.local("o/Paragraph"),
            url.local("o/ActionItem"),
        ],
        url.atomic("properties/properties"): [
            url.local("o/title"),
            url.local("o/subtitle"),
            url.local("o/elements"),
            url.local("o/approvedOn"),
            url.local("o/updatedOn"),
            url.local("o/retiredOn"),
            url.local("o/staleOn"),
            url.local("o/text"),
            url.local("o/titleLevel"),
        ],
        url.atomic("properties/instances"): [],
    }


def _build_Program() -> dict:
    return {
        "@id": url.local("o/Program"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "program",
        url.atomic("properties/description"): "Ohjelma.",
        url.atomic("properties/isA"): [url.atomic("classes/Class")],
        url.atomic("properties/requires"): [
            url.local("o/title"),
            url.local("o/elements"),
        ],
        url.atomic("properties/recommends"): [
            url.local("o/subtitle"),
            url.local("o/approvedOn"),
            url.local("o/updatedOn"),
            url.local("o/retiredOn"),
            url.local("o/staleOn"),
        ],
    }


def _build_Title() -> dict:
    return {
        "@id": url.local("o/Title"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "title",
        url.atomic("properties/description"): _markdown(
            """
            Otsikko (ohjelman solu).

            Ylimmän tason otsikon `titleLevel` on 1, sitä alemman väliotsikon
            2, ja niin edelleen.
            """
        ),
        url.atomic("properties/isA"): [url.atomic("classes/Class")],
        url.atomic("properties/requires"): [
            url.local("o/text"),
            url.local("o/titleLevel"),
        ],
    }


def _build_Paragraph() -> dict:
    return {
        "@id": url.local("o/Paragraph"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "paragraph",
        url.atomic("properties/description"): _markdown(
            """
            Leipätekstin kappale (ohjelman solu).

            Tämä on "tavallinen" tekstikappale. Erityisille elementeille, kuten
            otsikoille, linjauksille ja ohjelmamoduuleille, tulee käyttää niitä
            varten tehtyjä, erityisiä luokkia.
            """
        ),
        url.atomic("properties/isA"): [url.atomic("classes/Class")],
        url.atomic("properties/requires"): [
            url.local("o/text"),
        ],
    }


def _build_ActionItem() -> dict:
    return {
        "@id": url.local("o/ActionItem"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "actionitem",
        url.atomic("properties/description"): _markdown(
            """
            Linjaus (ohjelman solu).

            Tuttavallisemmin luetelmapallura.
            """
        ),
        url.atomic("properties/isA"): [url.atomic("classes/Class")],
        url.atomic("properties/requires"): [
            url.local("o/text"),
        ],
    }


def _build_title() -> dict:
    return {
        "@id": url.local("o/title"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "title",
        url.atomic("properties/description"): _markdown(
            """
            Ohjelman otsikko.

            Tämä on ohjelman varsinainen otsikko, siis esimerkiksi
            _Ihmislähtöinen ja kestävä digitalisaatio_.
            Lisäksi ohjelmalla voi olla alaotsikko `subtitle`, esimerkiksi
            _Tietopoliittinen ohjelma_.
            """),
        url.atomic("properties/datatype"): url.atomic("datatypes/string"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_subtitle() -> dict:
    return {
        "@id": url.local("o/subtitle"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "subtitle",
        url.atomic("properties/description"): _markdown(
            """
            Ohjelman alaotsikko.

            Esimerkiksi _Tietopoliittinen ohjelma_.
            """
        ),
        url.atomic("properties/datatype"): url.atomic("datatypes/string"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_elements() -> dict:
    return {
        "@id": url.local("o/elements"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "elements",
        url.atomic("properties/description"): _markdown(
            """
            Ohjelman sisältö.

            Sisältö ilmaistaan listana, jossa listan jokainen alkio on
            ohjelmatekstin pieni osa, esimerkiksi tekstikappale, otsikko, kuva
            tai luetelmakohta (nämä jälkimmäiset ovat meillä _linjauksia_).
            Nyrkkisääntönä voi pitää, että osat ovat sellaisia,  että niiden
            väliin voi tulla Markdownissa tyhjä rivi -- siis esimerkiksi
            kappaletta ei tule jakaa osiin tällä tavalla.
        """
        ),
        url.atomic("properties/datatype"): url.atomic("datatypes/resourceArray"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_approvedOn() -> dict:
    return {
        "@id": url.local("o/approvedOn"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "approvedon",
        url.atomic("properties/description"): _markdown(
            """
            Päivämäärä, jona ohjelman voimassaolo alkaa.
            """
        ),
        url.atomic("properties/datatype"): url.atomic("datatypes/date"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_updatedOn() -> dict:
    return {
        "@id": url.local("o/updatedOn"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "updatedon",
        url.atomic("properties/description"): _markdown(
            """
            Päivämäärä, jona ohjelmaa viimeksi päivitettiin.
            """
        ),
        url.atomic("properties/datatype"): url.atomic("datatypes/date"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_retiredOn() -> dict:
    return {
        "@id": url.local("o/retiredOn"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "retiredon",
        url.atomic("properties/description"): _markdown(
            """
            Päivämäärä, jona ohjelman voimassaolo päättyy.
            """
        ),
        url.atomic("properties/datatype"): url.atomic("datatypes/date"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_staleOn() -> dict:
    return {
        "@id": url.local("o/staleOn"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "staleon",
        url.atomic("properties/description"): _markdown(
            """
            Päivämäärä, jona ohjelma alkaa kantaa ajantasaisuusvaroitusta.

            Varoituksen päivämäärä voidaan asettaa etukäteen esimerkiksi 8
            vuoden päähän voimaantulosta, tai varoitus voidaan lisätä tarpeen
            tullen välittömänä.
            """
        ),
        url.atomic("properties/datatype"): url.atomic("datatypes/date"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_text() -> dict:
    return {
        "@id": url.local("o/text"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "text",
        url.atomic("properties/description"): "Tekstisisältö (markdown-muodossa).",
        url.atomic("properties/datatype"): url.atomic("datatypes/markdown"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _build_titleLevel() -> dict:
    return {
        "@id": url.local("o/titleLevel"),
        url.atomic("properties/parent"): url.local("o"),
        url.atomic("properties/shortname"): "titlelevel",
        url.atomic("properties/description"): _markdown(
            """
            Otsikon taso.

            Pääotsikon taso on 1, sen alla olevan väliotsikon taso on 2, ja
            niin edelleen.
        """
        ),
        url.atomic("properties/datatype"): url.atomic("datatypes/integer"),
        url.atomic("properties/isA"): [url.atomic("classes/Property")],
    }


def _markdown(s: str) -> str:
    return "\n".join([e.strip() for e in s.strip().split("\n")])
