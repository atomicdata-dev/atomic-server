import generate_ld


generate_ld.io.write(generate_ld.ontology.build(), "ontology")

# Oikeat ohjelmat...


def generate_program(md, name, title, **kwargs):
    generate_ld.io.write(
        generate_ld.program.build(
            md,
            name=name,
            title=title,
            **kwargs,
        ),
        name,
    )


#Vihreiden tietopoliittinen ohjelma Hyväksytty valtuuskunnan kokouksessa 16.5.2021, päivitetty puoluevaltuustossa 18.2.2024
generate_program(
    "md/tietopoliittinen-ohjelma.md",
    "p0",
    "Ihmislähtöinen ja kestävä digitalisaatio",
    subtitle="Tietopoliittinen ohjelma",
    approved_on="2021-05-16",
    updated_on="2024-2-18",
)

# Tämän ohjelman lisäksi maatalouspolitiikkaa ja sitä sivuavia teemoja käsitellään mm. puolueen maaseutu- ja aluepoliittisessa ohjelmassa (hyväksytty 25.9.2022) ja ruokapoliittisessa ohjelmassa ”Sydämen ja omantunnon lautanen” (hyväksytty 1.10.2010).
generate_program(
    "md/maatalousohjelma.md",
    "p1",
    "Kohti kestävämpää ja reilumpaa maataloutta",
    subtitle="Maatalouspoliittinen ohjelma",
    approved_on="2018-09-09",
    updated_on="2022-11-27",
)

#Vihreä elinkei­no­po­liit­tinen ohjelma Hyväksytty puoluevaltuuston kokouksessa 12.2.2023
generate_program(
    "md/elinkeinopoliittinen-ohjelma.md",
    "p2",
    "Talouden avulla tavoitteisiin",
    subtitle="Elinkeinopoliittinen ohjelma",
    approved_on="2023-02-12",
)

#Vihreiden ohjelma suurille kaupungeille Vihreiden puoluevaltuuston hyväksymä 19.5.2024
generate_program(
    "md/vihreiden-ohjelma-suurille-kaupungeille.md",
    "p3",
    "Huomisen kestävät ja viihtyisät kaupungit",
    subtitle="Vihreiden ohjelma suurille kaupungeille",
    approved_on="2024-05-19",
)

#Vihreät ratkaisut yksityishenkilöiden ylivelkaantumiseen *Hyväksytty puoluevaltuuston kokouksessa 18.2.2024*
generate_program(
    "md/vihreat-ratkaisut-yksityishenkiloiden-ylivelkaantumiseen.md",
    "p4",
    "Ei enää toivottomia velkavuoria",
    subtitle="Vihreät ratkaisut yksityishenkilöiden ylivelkaantumiseen",
    approved_on="2024-05-19",
)

#Oikeuspo­liit­tinen ohjelma *Hyväksytty puoluevaltuuston kokouksessa 18.2.2024*
generate_program(
    "md/oikeuspoliittinen-ohjelma.md",
    "p5",
    "Oikeuspo­liit­tinen ohjelma",
    approved_on="2024-02-18",
)

#Tasa-arvo- ja yhdenvertaisuusohjelma *Hyväksytty puoluevaltuuston kokouksessa 26.11.2023* Tämä ohjelma korvaa aiemman Vihreiden yhdenvertaisuusohjelman (2010) ja Vihreiden tasa-arvopoliittisen linjapaperin ”Tasa-arvo ei ole valmis” (2014), sekä kannanoton ”Askeleet translain uudistamiseksi” (2019).
#Tarkastusvuosi, jonka aikana puoluevaltuuston kokouksessa linjataan, onko tarvetta uudelle ohjelmalle, ohjelman hienovaraisemmalle päivitykselle tai ohjelman linjaamiselle vanhentuneeksi: 2027.

generate_program(
    "md/tasa-arvo-ja-yhdenvertaisuusohjelma.md",
    "p6",
    "Tasa-arvo- ja yhdenvertaisuusohjelma",
    approved_on="2023-11-26",
)

#Ulko- ja turvalli­suus­po­liit­tinen ohjelma  *Hyväksytty puoluevaltuuston kokouksessa 24.9.2023.*
#*Tarkastusvuosi, jonka aikana puoluevaltuuston kokouksessa linjataan, onko tarvetta uudelle ohjelmalle, ohjelman hienovaraisemmalle päivitykselle tai ohjelman linjaamiselle vanhentuneeksi: 2027.*
generate_program(
    "md/ulko-ja-turvallisuuspoliittinen-ohjelma.md",
    "p7",
    "Ulko- ja turvalli­suus­po­liit­tinen ohjelma",
    approved_on="2023-09-24",
)

#Vihreiden tiedepoliittinen ohjelma *Hyväksytty puoluevaltuuston kokouksessa 14.5.2023*
#*Tarkastusvuosi, jonka aikana puoluevaltuuston kokouksessa linjataan, onko tarvetta uudelle ohjelmalle, ohjelman hienovaraisemmalle päivitykselle tai ohjelman linjaamiselle vanhentuneeksi: 20xx*
generate_program(
    "md/tiedepoliittinen-ohjelma.md",
    "p8",
    "Tiedepoliittinen ohjelma",
    approved_on="2023-05-14",
)

#Vihreiden energiavisio 2035 *Hyväksytty puoluevaltuuston kokouksessa 27.2.2023*
generate_program(
    "md/vihreiden-energiavisio-2035.md",
    "p9",
    "Vihreiden energiavisio 2035",
    approved_on="2023-02-27",
)

#Vihreiden maahanmuuttopoliittinen ohjelma *Hyväksytty puoluevaltuuston kokouksessa 27.11.2022*
generate_program(
    "md/vihreiden-maahanmuuttopoliittinen-ohjelma.md",
    "p10",
    "Maahanmuuttopoliittinen ohjelma",
    approved_on="2022-11-27",
)

#Vihreiden liikennepoliittinen ohjelma *Hyväksytty puoluevaltuuston kokouksessa 25.9.2022*
generate_program(
    "md/vihreiden-maahanmuuttopoliittinen-ohjelma.md",
    "p11",
    "Visio liikenteen tulevaisuudesta",
    subtitle="liikennepoliittinen ohjelma",
    approved_on="2022-09-25",
)

#Vihreä maaseutu- ja aluepoliittinen ohjelma *Hyväksytty puoluevaltuuston kokouksessa 25.9.2022*
generate_program(
    "md/vihrea-maaseutu-ja-aluepoliittinen-ohjelma.md",
    "p12",
    "Vihreässä Suomessa ihmisillä on toivoa ympäri maata",
    subtitle="Vihreä maaseutu- ja aluepoliittinen ohjelma",
    approved_on="2022-09-25",
)

#Vihreiden poliittinen ohjelma 2023–2027 *Hyväksytty puoluekokouksessa 22.5.2022*
generate_program(
    "md/vihreiden-poliittinen-ohjelma-2023-2027.md",
    "p13",
    "Vihreiden poliittinen ohjelma 2023–2027",
    approved_on="2022-05-22",
)

#Vihreiden vesiensuo­je­luoh­jelma *Hyväksytty puoluevaltuuskunnan kokouksessa 24.4.2022*
generate_program(
    "md/vihreiden-vesiensuojeluohjelma.md",
    "p14",
    "Vihreiden vesiensuo­je­luoh­jelma",
    approved_on="2022-04-24",
)

#Kaikkien sosiaaliturva *Vihreiden sosiaaliturvaohjelma *Hyväksytty puoluevaltuuskunnan kokouksessa 20.2.2022*
#*Tämä ohjelma korvaa puoluehallituksen 1.11.2014 hyväksymän perustulolinjapaperin, puoluehallituksen 5.2.2019 hyväksymän päivitetyn perustulomallin sekä puoluehallituksen 4.2.2011 hyväksymät Vihreät eläkelinjaukset.*
generate_program(
    "md/kaikkien-sosiaaliturva-vihreiden-sosiaaliturvaohjelma.md",
    "p15",
    "Kaikkien sosiaaliturva",
    subtitle="Vihreiden sosiaaliturvaohjelma",
    approved_on="2022-02-20",
)

#Vihreä kulttuurimanifesti ja kulttuuripoliittinen ohjelma *Hyväksytty puoluevaltuuskunnan kokouksessa 20.2.2022*
#*Tämä ohjelma korvaa valtuuskunnan 27.5.2018 hyväksymän kulttuuripoliittisen ohjelman.*
generate_program(
    "md/vihrea-kulttuurimanifesti-ja-kulttuuripoliittinen-ohjelma.md",
    "p16",
    "Kulttuuripoliittinen ohjelma",
    approved_on="2022-02-20",
)

#Vihreiden aluevaaliohjelma *Hyväksytty puoluevaltuuskunnan kokouksessa 21.11.2021*
generate_program(
    "md/aluevaaliohjelma-2021.md",
    "p17",
    "Vihreiden aluevaaliohjelma",
    approved_on="2021-11-21",
)

#Vihreä Eurooppa-ohjelma *Hyväksytty puoluevaltuuskunnan kokouksessa 3.10.2021*
generate_program(
    "md/vihrea-eurooppa-ohjelma.md",
    "p18",
    "Vihreä Eurooppa-ohjelma",
    approved_on="2021-10-03",
)

#Vihreiden työllisyyspoliittiset linjaukset 2021 *Hyväksytty puoluevaltuuskunnan kokouksessa 16.5.2021* täsmennetty puoluevaltuustossa 18.2.2024*
generate_program(
    "md/vihreiden-tyollisyyspoliittiset-linjaukset-2021.md",
    "p19",
    "Koulutusta, kannustavuutta ja turvaa",
    subtitle="Vihreiden työllisyyspoliittiset linjaukset 2021",
    approved_on="2021-05-16",
    updated_on="2024-02-18",
)

#Lapsi- ja nuorisopoliittinen ohjelma *Hyväksytty puoluevaltuuskunnan kokouksessa 21.2.2021* päivitetty 20.2.2022
#*Tämä ohjelma korvaa puoluehallituksen 26.11.2010 hyväksymän lapsipoliittisen linjapaperin.*
generate_program(
    "md/lapsi-ja-nuorisopoliittinen-ohjelma.md",
    "p20",
    "Lapsi- ja nuorisopoliittinen ohjelma",
    approved_on="2021-02-21",
    updated_on="2022-02-20",
)

#Metsäpoliittinen ohjelma *Hyväksytty puoluevaltuuskunnan kokouksessa 29.11.2020*
#*Hyväksytty puoluevaltuuskunnan kokouksessa 29.11.2020. Tämä ohjelma korvaa ohjelmapaperin "Vihreät timantit – metsäsektorin kestävä uudistaminen (2008)"*  
generate_program(
    "md/metsapoliittinen-ohjelma.md",
    "p21",
    "Metsäpoliittinen ohjelma",
    approved_on="2020-11-29",
)

#Kunta- ja kaupunkivisio *Hyväksytty puoluevaltuuskunnan kokouksessa 27.9.2020*
generate_program(
    "md/kunta-ja-kaupunkivisio.md",
    "p22",
    "Kunta- ja kaupunkivisio",
    approved_on="2020-09-27",
)

#Ikääntymispoliittinen ohjelma *Hyväksytty puoluevaltuuskunnan kokouksessa 27.9.2020*
generate_program(
    "md/ikaantymispoliittinen-ohjelma.md",
    "p23",
    "Ikääntymispoliittinen ohjelma",
    approved_on="2020-09-27",
)

#Vihreät muuttavat maailmaa, jotta elämä maapallolla voi kukoistaa Vihreiden periaateohjelma 2020-2028 *Hyväksytty puoluekokouksessa 20.9.2020. Tämä ohjelma korvaa edellisen, vuoden 2012 puoluekokouksessa hyväksytyn periaateohjelman.*
generate_program(
    "md/periaateohjelma-2020-2028.md",
    "p24",
    "Vihreät muuttavat maailmaa, jotta elämä maapallolla voi kukoistaa",
    subtitle="Vihreiden periaateohjelma 2020-2028",
    approved_on="2020-09-20",
)

#Miten päästöjä ja köyhyyttä vähennetään samaan aikaan? Reilun vihreän muutoksen ohjelma *Hyväksytty puoluevaltuuskunnan kokouksessa 23.2.2020*
generate_program(
    "md/reilun-vihrean-muutoksen-ohjelma.md",
    "p25",
    "Miten päästöjä ja köyhyyttä vähennetään samaan aikaan?",
    subtitle="Reilun vihreän muutoksen ohjelma",
    approved_on="2020-02-23",
)

#Eurovaaliohjelma 2024 *Hyväksytty puoluevaltuustossa 18.2.2024*
generate_program(
    "md/eurovaaliohjelma-2024.md",
    "p26",
    "Rakennetaan uutta, luodaan toivoa, suojellaan arvokkainta",
    subtitle="Eurovaaliohjelma 2024",
    approved_on="2024-02-18",
)

#Suojele elämää Vihreiden eduskuntavaaliohjelma 2023 *Hyväksymispäivänmäärää ei lue vihreiden sivuilla?
generate_program(
    "md/suojele-elamaa-vihreiden-eduskuntavaaliohjelma-2023.md",
    "p27",
    "Suojele elämää",
    subtitle="Eduskuntavaaliohjelma 2023",
    approved_on="2023-00-00",
)

#Vihreiden Lukeva Suomi -teesit *Hyväksytty puoluevaltuuskunnan kokouksessa 3.12.2017*
generate_program(
    "md/vihreiden-lukeva-suomi-teesit.md",
    "p28",
    "Vihreiden Lukeva Suomi -teesit",
    approved_on="2017-12-03",
)

#Pelastetaan maailman paras koulutus *Hyväksytty puoluevaltuuskunnan kokouksessa 17.11.2018* Tämä ohjelma korvaa 23.11.2014 hyväksytyn koulutuspoliittisen ohjelman.*
generate_program(
    "md/pelastetaan-maailman-paras-koulutus.md",
    "p29",
    "Pelastetaan maailman paras koulutus",
    subtitle="koulutuspoliittinen ohjelma",
    approved_on="2018-11-17",
)

#Luonto vastuullamme Vihreiden luonnonsuojeluohjelma *Hyväksytty valtuuskunnan kokouksessa 4.3.2018. Tämä ohjelma korvaa puoluehallituksen 1.10.2010 hyväksymät ja puoluevaltuuskunnan 30.9.2012 muokkaamat Vihreiden luonnonsuojelutavoitteet.*
generate_program(
    "md/luonto-vastuullamme-vihreiden-luonnonsuojeluohjelma.md",
    "p30",
    "Luonto vastuullamme",
    subtitle="Vihreiden luonnonsuojeluohjelma",
    approved_on="2018-03-04",
)

#Kulttuuripoliittinen ohjelma *Hyväksytty valtuuskunnan kokouksessa 27.5.2018*
generate_program(
    "md/kulttuuripoliittinen-ohjelma.md",
    "p31",
    "Kulttuuripoliittinen ohjelma",
    approved_on="2018-05-27",
    retired_on="2022-02-20",
)




# Testiohjelmat...


def generate_test(name, kind, **kwargs):
    generate_program(
        "md/tietopoliittinen-ohjelma.md",
        name,
        "Lorem ipsum dolor sit amet",
        subtitle=f"TESTIOHJELMA ({kind})",
        **kwargs,
    )


generate_test("px_luo", "luonnos")
generate_test("px_hyv", "voimassa", approved_on="2021-01-01")
generate_test("px_van", "vanhentunut", approved_on="2021-01-01", stale_on="2022-05-03")
generate_test(
    "px_poi",
    "poistunut",
    approved_on="2021-01-01",
    stale_on="2022-05-03",
    retired_on="2023-10-05",
)
