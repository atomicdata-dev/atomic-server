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


generate_program(
    "md/tietopoliittinen-ohjelma.md",
    "p0",
    "Ihmislähtöinen ja kestävä digitalisaatio",
    subtitle="Tietopoliittinen ohjelma",
    approved_on="2021-05-16",
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
