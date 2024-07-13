import generate_ld


generate_ld.io.write(generate_ld.ontology.build(), "ontology")

# Oikeat ohjelmat...

generate_ld.io.write(
    generate_ld.program.build(
        "md/tietopoliittinen-ohjelma.md",
        name="p0",
        title="Ihmislähtöinen ja kestävä digitalisaatio",
        subtitle="Tietopoliittinen ohjelma",
        approved_on="2021-05-16",
    ),
    "tietopoliittinen-ohjelma",
)


# Testiohjelmat...


def generate_test(name, kind, **kwargs):
    generate_ld.io.write(
        generate_ld.program.build(
            "md/tietopoliittinen-ohjelma.md",
            name=name,
            title="Lorem ipsum dolor sit amet",
            subtitle=f"TESTIOHJELMA ({kind})",
            **kwargs,
        ),
        name,
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
