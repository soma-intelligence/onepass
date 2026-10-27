"""Parse onepass-core templates.rs and menus.rs: template labels and menu options."""
import re, sys, json

def camel(v):
    return v[0].lower() + v[1:]

def parse(core):
    src = open(f"{core}/onepass-core/src/model/templates.rs").read()
    src = src.split("#[cfg(test)]")[0]
    tmap = dict(re.findall(r"ItemType::(\w+) => (\w+)\(\),", src))
    out = {}
    for variant, fn in tmap.items():
        m = re.search(r"\nfn " + fn + r"\(\) -> Vec<Section> \{(.*?)\n\}\n", src, re.S)
        body = m.group(1)
        sections, fields = [], []
        for kind, a, b in re.findall(r'\b(sec|tx|pw|cn|url|em|ph|dt|my|num|mon|adr|menu|otp|file|link|yn|fld)\(\s*"([^"]+)",\s*"([^"]+)"', body):
            (sections if kind == "sec" else fields).append((a, b))
        out[camel(variant)] = {"sections": sections, "fields": fields}
    msrc = open(f"{core}/onepass-core/src/model/menus.rs").read().split("#[cfg(test)]")[0]
    options = sorted(set(re.findall(r'"([^"]+)"', msrc.split("pub fn menu_options")[1])) | {"oui", "non"})
    # drop field ids that appear in the match patterns
    ids = set(re.findall(r'T::\w+(?: \| T::\w+)*,\s*"([^"]+)"', msrc)) | set(re.findall(r'"(\w+)"\s*(?:\||\))', msrc))
    options = [o for o in options if not re.fullmatch(r"[a-z_]+", o) or o in ("oui", "non")]
    return out, options

if __name__ == "__main__":
    t, o = parse(sys.argv[1])
    json.dump({"templates": t, "options": o}, sys.stdout, ensure_ascii=False, indent=1)
