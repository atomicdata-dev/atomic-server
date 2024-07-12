import generate_ld


generate_ld.io.write(generate_ld.ontology.build(), "ontology")

generate_ld.io.write(
    generate_ld.program.build(
        "md/tietopoliittinen-ohjelma.md",
        name="p0",
        title="Tietopoliittinen ohjelma",
        approved_on="2021-05-16",
    ),
    "tietopoliittinen-ohjelma",
)
