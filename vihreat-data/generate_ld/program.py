from generate_ld import url


def build(markdown_path: str, **kwargs) -> list[dict]:
    elements = _build_elements(markdown_path, kwargs["name"])
    main = _build_main(elements, **kwargs)
    return elements + [main]


def _build_main(elements: list[dict], name: str, title: str, approved_on: str) -> dict:
    return {
        "@id": url.local(f"ohjelmat/{name}"),
        url.atomic("properties/parent"): url.local(),
        url.atomic("properties/isA"): [url.local("o/Program")],
        url.local("o/title"): title,
        url.local("o/elements"): [e["@id"] for e in elements],
        url.local("o/approvedOn"): approved_on,
    }


def _build_elements(markdown_path: str, parent_name: str) -> list[dict]:
    elements = []
    with open(markdown_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                elements.append(_build_element(line, parent_name, len(elements)))
    return elements


def _build_element(line: str, parent_name: str, num: int) -> dict:
    name = f"{parent_name}e{num}"
    if line.startswith("#"):
        return {
            "@id": url.local(f"ohjelmat/{name}"),
            url.atomic("properties/isA"): [url.local("o/Title")],
            url.local("o/text"): line.lstrip("# "),
            url.local("o/titleLevel"): len(line) - len(line.lstrip("#")),
        }
    elif line.startswith("* "):
        return {
            "@id": url.local(f"ohjelmat/{name}"),
            url.atomic("properties/isA"): [url.local("o/ActionItem")],
            url.local("o/text"): line[1:].strip(),
        }
    else:
        return {
            "@id": url.local(f"ohjelmat/{name}"),
            url.atomic("properties/isA"): [url.local("o/Paragraph")],
            url.local("o/text"): line,
        }
