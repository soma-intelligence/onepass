#!/usr/bin/env python3
"""Fill every missing translation of the Apple String Catalogs in one pass, with a language model.

    python3 -I apple/scripts/translate-strings.py            # translate what is missing, write
    python3 -I apple/scripts/translate-strings.py --dry-run  # count what is missing, call nothing

Adding a string only needs its French value (and a comment) in the catalog; this command writes
every other language listed in `scripts/i18n/config.json` (`languages`). It also fills missing
columns of `scripts/i18n/glossary.json`, then copies the glossary into the `term.*` / `common.*`
entries (`i18n.py sync`).

What it does:
- scans `apple/**/*.xcstrings` (build folders excluded, `apple/Vendor` included); an entry is to
  do for a language when it has no value there, an empty one, or one still in the `new` state;
- sends batches to an OpenAI-compatible Chat Completions endpoint with the French source, the
  English when there is one, the comment, the glossary and the house rules (tu, Apple's own words);
- keeps the structure of the source (plural and device variations, substitutions, App Shortcuts
  phrase sets) and checks every value: same format specifiers (`%@`, `%lld`, positional `%1$@`),
  same `${applicationName}` and `{name}` placeholders, same Markdown marks, brands kept
  (OnePass, Watchtower, Secret Key, Emergency Kit, Travel Mode), no em dash. A value that fails is
  asked again once, then left out and listed;
- writes machine output in the `needs_review` state, so Xcode and `i18n.py check -v` show what a
  person has not read yet. A reviewer sets it to `translated` (Xcode: Mark as Reviewed).

Configuration (environment, or `apple/scripts/personal.env`, which is gitignored):
  ONEPASS_TRANSLATE_BASE_URL  OpenAI-compatible base URL, e.g. https://<resource>.openai.azure.com/openai/v1
  ONEPASS_TRANSLATE_MODEL     model or Azure deployment name (default gpt-6.1-sol)
  ONEPASS_TRANSLATE_KEY       API key, or
  ONEPASS_TRANSLATE_KEY_CMD   a command that prints it (e.g. `az cognitiveservices account keys list ...`)

Standard library only. See docs/i18n.md.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import copy
import glob
import http.client
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts", "i18n"))
import i18n  # noqa: E402

BRANDS = ["OnePass", "Watchtower", "Secret Key", "Emergency Kit", "Travel Mode"]
BUILD_DIRS = ("/.build/", "/build/", "/DerivedData")

NAMES = {
    "fr": "French", "en": "English", "es": "Spanish", "it": "Italian", "de": "German",
    "ko": "Korean", "zh-Hans": "Simplified Chinese", "ja": "Japanese", "pt-BR": "Brazilian Portuguese",
    "nl": "Dutch", "zh-Hant": "Traditional Chinese",
}
STYLE = {
    "en": "US English. Titles and buttons in Title Case, sentences in sentence case.",
    "es": "Address the user with tú. Sentence case for titles and buttons. Apple's Spanish UI words (Ajustes, llave de acceso).",
    "it": "Address the user with tu. Sentence case. Apple's Italian UI words (Impostazioni, Riempimento automatico).",
    "de": "Address the user with du (informal, lower-case du/dein). Sentence case except nouns. Apple's German UI words (Einstellungen, Passwort, Passkey, Sichern).",
    "ko": "Polite informal register (해요체), as in Apple's Korean UI. Apple's Korean UI words (설정, 암호, 패스키). Keep it short.",
    "zh-Hans": "Address the user with 你. Apple's Simplified Chinese UI words (设置, 密码, 通行密钥, 存储, 拷贝). Full-width punctuation; a space between Chinese and Latin words or numbers, as Apple does.",
}

MD_MARKS = re.compile(r"\*\*|__|`|\]\(")


# --- configuration ------------------------------------------------------------------------------

def load_env_file(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            os.environ.setdefault(k.strip(), v)


class Client:
    def __init__(self, base_url: str, model: str, key: str, effort: str | None) -> None:
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.key = key
        self.effort = effort
        self.lock = threading.Lock()
        self.calls = 0

    def complete(self, system: str, user: str) -> dict:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_object"},
        }
        if self.effort:
            body["reasoning_effort"] = self.effort
        data = json.dumps(body).encode()
        headers = {"Content-Type": "application/json", "api-key": self.key, "Authorization": f"Bearer {self.key}"}
        delay = 4.0
        for attempt in range(6):
            req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=600) as r:
                    out = json.loads(r.read())
                with self.lock:
                    self.calls += 1
                text = out["choices"][0]["message"]["content"]
                return json.loads(text)
            except urllib.error.HTTPError as e:
                if e.code in (408, 409, 429, 500, 502, 503, 504) and attempt < 5:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise RuntimeError(f"HTTP {e.code}: {e.read()[:300]!r}") from None
            except (OSError, http.client.HTTPException, json.JSONDecodeError, KeyError, IndexError) as e:
                if attempt < 5:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise RuntimeError(str(e)) from None
        raise RuntimeError("unreachable")


def make_client(args) -> Client:
    load_env_file(os.path.join(HERE, "personal.env"))
    base = os.environ.get("ONEPASS_TRANSLATE_BASE_URL")
    key = os.environ.get("ONEPASS_TRANSLATE_KEY")
    if not key and os.environ.get("ONEPASS_TRANSLATE_KEY_CMD"):
        key = subprocess.run(shlex.split(os.environ["ONEPASS_TRANSLATE_KEY_CMD"]), capture_output=True,
                             text=True, check=True).stdout.strip()
    if not base or not key:
        sys.exit("Set ONEPASS_TRANSLATE_BASE_URL and ONEPASS_TRANSLATE_KEY (or _KEY_CMD), "
                 "in the environment or apple/scripts/personal.env. See the top of this file.")
    model = args.model or os.environ.get("ONEPASS_TRANSLATE_MODEL") or "gpt-6.1-sol"
    effort = args.effort or os.environ.get("ONEPASS_TRANSLATE_EFFORT") or None
    return Client(base, model, key, effort)


# --- catalogs -----------------------------------------------------------------------------------

def catalogs(only: list[str] | None) -> list[str]:
    out = []
    for p in sorted(glob.glob(os.path.join(ROOT, "apple", "**", "*.xcstrings"), recursive=True)):
        r = "/" + i18n.rel(p)
        if any(b in r for b in BUILD_DIRS):
            continue
        if only and not any(o in r for o in only):
            continue
        out.append(p)
    return out


def leaf_list(loc: dict) -> list[tuple[tuple, str]]:
    return [(path, unit.get("value", "")) for path, unit in i18n.leaves(loc)]


def needs(loc: dict | None) -> bool:
    if not loc:
        return True
    lv = list(i18n.leaves(loc))
    if not lv:
        return True
    return any(not u.get("value") or u.get("state") == "new" for _, u in lv)


def rebuild(src: dict, values: dict[tuple, str]) -> dict:
    """A copy of the source localization with each leaf replaced, marked needs_review."""
    out = copy.deepcopy(src)

    def walk(loc: dict, path: tuple) -> None:
        if "stringUnit" in loc:
            loc["stringUnit"] = {"state": "needs_review", "value": values[path]}
        if "stringSet" in loc:
            n = len(loc["stringSet"].get("values", []))
            loc["stringSet"] = {"state": "needs_review", "values": [values[path + ("set", str(i))] for i in range(n)]}
        for kind, cases in loc.get("variations", {}).items():
            for case, sub in cases.items():
                walk(sub, path + (kind, case))
        for name, sub in loc.get("substitutions", {}).items():
            walk(sub, path + ("subst", name))

    walk(out, ())
    return out


# --- checks -------------------------------------------------------------------------------------

def problems(src: str, got: str, path: tuple) -> list[str]:
    out = []
    if not got.strip() and src.strip():
        return ["empty"]
    ref, sig = i18n.printf_signature(src), i18n.printf_signature(got)
    partial = ("plural" in path and path[-1] != "other") or (path and path[0] == "device")
    if partial:
        if not set(sig) <= set(ref):
            out.append(f"placeholders {sorted(sig)} not in source {sorted(ref)}")
    elif not i18n.same_args(ref, sig):
        out.append(f"placeholders {sorted(sig)} != {sorted(ref)}")
    if i18n.named_signature(src) != i18n.named_signature(got):
        out.append("{name} placeholders differ")
    if collections.Counter(MD_MARKS.findall(src)) != collections.Counter(MD_MARKS.findall(got)):
        out.append("Markdown marks differ")
    for b in BRANDS:
        if b in src and b not in got:
            out.append(f"brand {b} missing")
    if i18n.EM_DASH in got:
        out.append("em dash")
    return out


# --- prompts ------------------------------------------------------------------------------------

def system_prompt(lang: str, glossary: dict, source: str) -> str:
    rows = []
    for key, g in glossary.items():
        if g.get(lang):
            rows.append(f"- {g.get(source, '')} / {g.get('en', '')} => {g[lang]}" + (f"  ({g['note']})" if g.get("note") else ""))
    return (
        f"You translate the user interface of OnePass, a password manager for iPhone, iPad, Mac, Apple Watch "
        f"and Vision Pro, into {NAMES.get(lang, lang)} ({lang}). The source language is {NAMES.get(source, source)}; "
        f"an English version is given as a reference when there is one.\n\n"
        f"Rules:\n"
        f"- Short, plain, Apple-like UI text. Use the words Apple's own {NAMES.get(lang, lang)} UI uses.\n"
        f"- {STYLE.get(lang, '')}\n"
        f"- Keep every format specifier exactly (%@, %lld, %d, %1$@, %2$lld, %%). If the word order changes, use "
        f"positional specifiers (%1$@, %2$lld) with the same types. Keep ${{applicationName}} and {{name}} placeholders.\n"
        f"- Keep Markdown (**bold**, `code`, [text](url)) and keep URLs, emails, file names and code untouched.\n"
        f"- Never translate these brand and feature names: {', '.join(BRANDS)}.\n"
        f"- Never use an em dash. Use a comma, a colon, a period or parentheses.\n"
        f"- A 'one' plural case may drop the number; the 'other' case keeps it.\n"
        f"- Text with no letters to translate (a symbol, a number format) stays as it is.\n"
        f"- Product terms, always these words (source / English => {lang}):\n" + "\n".join(rows) + "\n\n"
        f"Input: a JSON object {{\"items\": [{{\"id\", \"source\", \"en\"?, \"comment\"?, \"case\"?}}]}}. "
        f"Output: a JSON object {{\"translations\": {{\"<id>\": \"<{lang} text>\"}}}} with every id."
    )


# --- jobs ---------------------------------------------------------------------------------------

class Job:
    __slots__ = ("cat", "key", "lang", "src", "en", "comment", "leaves", "values", "errors")

    def __init__(self, cat, key, lang, src, en, comment):
        self.cat, self.key, self.lang, self.src, self.en, self.comment = cat, key, lang, src, en, comment
        self.leaves = leaf_list(src)
        self.values: dict[tuple, str] = {}
        self.errors: list[str] = []


def collect(paths: list[str], langs: list[str], cfg: dict, glossary: dict):
    loaded, jobs, skipped = {}, [], []
    for path in paths:
        cat = i18n.read_json(path)
        loaded[path] = cat
        source = cat.get("sourceLanguage", cfg["source"])
        for key, entry in cat.get("strings", {}).items():
            if not i18n.translatable(key, entry):
                continue
            if key in glossary:  # term.* / common.*: copied from the glossary by sync
                continue
            src = i18n.source_loc(key, entry, source)
            if src is None:
                skipped.append(f"{i18n.rel(path)} [{key}]: no '{source}' value")
                continue
            if not any(v.strip() for _, v in leaf_list(src)):
                continue
            locs = entry.get("localizations", {})
            for lang in langs:
                if lang == source or not needs(locs.get(lang)):
                    continue
                en = locs.get("en") if source != "en" else None
                jobs.append(Job(path, key, lang, src, en, entry.get("comment")))
    return loaded, jobs, skipped


def run_batch(client: Client, lang: str, system: str, batch: list[Job], source: str) -> None:
    items, index = [], {}
    for j_i, job in enumerate(batch):
        en_leaves = dict(leaf_list(job.en)) if job.en else {}
        en_plain = en_leaves.get(()) or en_leaves.get(("plural", "other")) or ""
        for l_i, (path, text) in enumerate(job.leaves):
            if path in job.values:
                continue
            ident = f"{j_i}.{l_i}"
            index[ident] = (job, path, text)
            item = {"id": ident, "source": text}
            en = en_leaves.get(path) or en_plain
            if en:
                item["en"] = en
            if job.comment:
                item["comment"] = job.comment
            if path:
                item["case"] = "/".join(p for p in path if p not in ("set",))
            items.append(item)
    if not items:
        return
    for attempt in range(2):
        todo = [it for it in items if index[it["id"]][1] not in index[it["id"]][0].values]
        if not todo:
            return
        try:
            out = client.complete(system, json.dumps({"items": todo}, ensure_ascii=False)).get("translations", {})
        except RuntimeError as e:
            for it in todo:
                index[it["id"]][0].errors.append(f"request failed: {e}")
            return
        for it in todo:
            job, path, text = index[it["id"]]
            got = out.get(it["id"])
            if not isinstance(got, str):
                if attempt:
                    job.errors.append(f"{'/'.join(path) or 'value'}: no answer")
                continue
            got = got.strip() if text == text.strip() else got
            bad = problems(text, got, path)
            if not bad:
                job.values[path] = got
            elif attempt:
                job.errors.append(f"{'/'.join(path) or 'value'}: {'; '.join(bad)} ({got!r})")
            else:
                it["previous"] = got
                it["fix"] = "; ".join(bad)


def fill_glossary(client: Client | None, cfg: dict, dry: bool) -> int:
    path = os.path.join(ROOT, cfg["glossary"])
    doc = i18n.read_json(path)
    entries = doc["entries"]
    missing = [(k, lang) for k, g in entries.items() for lang in cfg["languages"] if not g.get(lang)]
    if dry or not missing:
        return len(missing)
    by_lang = collections.defaultdict(list)
    for k, lang in missing:
        by_lang[lang].append(k)
    for lang, keys in by_lang.items():
        items = [{"id": k, "source": entries[k][cfg["source"]], "en": entries[k].get("en", ""), "comment": entries[k].get("note", "")} for k in keys]
        out = client.complete(system_prompt(lang, {}, cfg["source"]) + "\nThese are glossary terms: give the bare term.",
                              json.dumps({"items": items}, ensure_ascii=False)).get("translations", {})
        for k in keys:
            if isinstance(out.get(k), str) and out[k].strip():
                entries[k][lang] = out[k].strip()
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
    return len(missing)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="count what is missing, call nothing, write nothing")
    ap.add_argument("--lang", nargs="*", help="only these languages (default: config.json languages)")
    ap.add_argument("--only", nargs="*", help="only catalogs whose path contains one of these")
    ap.add_argument("--model", help="model or deployment (default: ONEPASS_TRANSLATE_MODEL or gpt-6.1-sol)")
    ap.add_argument("--effort", help="reasoning_effort sent to the model (default: none)")
    ap.add_argument("--batch", type=int, default=30, help="entries per request (default 30)")
    ap.add_argument("--jobs", type=int, default=8, help="parallel requests (default 8)")
    args = ap.parse_args(argv)

    cfg = i18n.load_config()
    langs = args.lang or [l for l in cfg["languages"]]
    client = None if args.dry_run else make_client(args)

    g_missing = fill_glossary(client, cfg, args.dry_run)
    glossary = i18n.load_glossary(cfg)
    paths = catalogs(args.only)
    loaded, jobs, skipped = collect(paths, langs, cfg, glossary)

    per = collections.Counter((i18n.rel(j.cat), j.lang) for j in jobs)
    for (cat, lang), n in sorted(per.items()):
        print(f"{cat}: {lang} {n}")
    print(f"{len(jobs)} entries to translate, {g_missing} glossary value(s) missing")
    if args.dry_run or not jobs:
        if not args.dry_run:
            i18n.cmd_sync(None)
        return 0

    work = []
    for lang in langs:
        lj = [j for j in jobs if j.lang == lang]
        if not lj:
            continue
        for path in {j.cat for j in lj}:
            source = loaded[path].get("sourceLanguage", cfg["source"])
            system = system_prompt(lang, glossary, source)
            cj = [j for j in lj if j.cat == path]
            for i in range(0, len(cj), args.batch):
                work.append((lang, system, cj[i:i + args.batch], source))
    state = {"written": 0, "failed": [], "flushed": set()}

    def flush(finished: list[Job]) -> None:
        """Write the finished jobs, catalog by catalog, so an interrupted run keeps its work."""
        by_cat = collections.defaultdict(list)
        for job in finished:
            if id(job) not in state["flushed"]:
                state["flushed"].add(id(job))
                by_cat[job.cat].append(job)
        for path, cj in by_cat.items():
            # Read the catalog again: Xcode or another branch may have changed it meanwhile.
            cat = i18n.read_json(path)
            source = cat.get("sourceLanguage", cfg["source"])
            dirty = False
            for job in cj:
                if job.errors or len(job.values) != len(job.leaves):
                    state["failed"].append(f"{i18n.rel(path)} [{job.key}] {job.lang}: " + ("; ".join(job.errors) or "incomplete"))
                    continue
                entry = cat["strings"].get(job.key)
                if entry is None or i18n.source_loc(job.key, entry, source) != job.src:
                    state["failed"].append(f"{i18n.rel(path)} [{job.key}] {job.lang}: source changed during the run, rerun")
                    continue
                if not needs(entry.get("localizations", {}).get(job.lang)):
                    continue
                entry.setdefault("localizations", {})[job.lang] = rebuild(job.src, job.values)
                dirty = True
                state["written"] += 1
            if dirty:
                i18n.write_xcstrings(path, cat)

    done, finished = 0, []
    print(f"{len(work)} requests to {client.model}, {args.jobs} at a time")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_batch, client, *w): w for w in work}
        for f in concurrent.futures.as_completed(futures):
            batch = futures[f][2]
            try:
                f.result()
            except Exception as e:  # one bad batch must not lose the others
                for job in batch:
                    job.errors.append(f"batch failed: {e}")
            finished.extend(batch)
            done += 1
            if done % 10 == 0 or done == len(futures):
                flush(finished)
                print(f"  {done}/{len(futures)} requests, {state['written']} entries written", flush=True)
    flush(finished)
    written, failed = state["written"], state["failed"]
    i18n.cmd_sync(None)
    print(f"{written} entries written (state needs_review), {len(failed)} left out, {client.calls} requests")
    for line in skipped + failed:
        print("  " + line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
