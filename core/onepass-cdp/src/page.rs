//! One page target: its top frame, its page context and the inputs that
//! type and click.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use onepass_core::fill_plan::context::{
    ButtonClass, ButtonContext, FieldContext, FieldRole, FormContext, FrameKind, IntentHints,
    MAX_BUTTONS, MAX_FIELDS, MAX_FORMS, PageContext, Prefilled,
};
use serde_json::{Value, json};

use crate::CdpError;
use crate::classify::{self, FieldFacts};
use crate::socket::Socket;

/// Styles asked of `DOMSnapshot.captureSnapshot`, in this order.
const STYLES: [&str; 3] = ["display", "visibility", "opacity"];
/// Headings read per form (`MAX_FORM_HEADINGS`).
const MAX_FORM_HEADINGS: usize = 5;
/// The only attributes kept from the snapshot.
const KEPT_ATTRS: [&str; 22] = [
    "id",
    "name",
    "type",
    "autocomplete",
    "placeholder",
    "aria-label",
    "aria-labelledby",
    "title",
    "for",
    "form",
    "role",
    "action",
    "href",
    "disabled",
    "readonly",
    "maxlength",
    "inputmode",
    "pattern",
    "value",
    "multiple",
    "aria-disabled",
    "hidden",
];
/// Input types that never hold a value OnePass fills.
const NON_FIELD_TYPES: [&str; 10] = [
    "hidden", "submit", "button", "reset", "image", "file", "radio", "range", "color", "search",
];
const INPUT_TYPES: [&str; 22] = [
    "text",
    "password",
    "email",
    "tel",
    "number",
    "url",
    "date",
    "month",
    "week",
    "time",
    "datetime-local",
    "checkbox",
    "radio",
    "hidden",
    "submit",
    "button",
    "reset",
    "image",
    "file",
    "range",
    "color",
    "search",
];

/// A page target reached over loopback.
pub struct CdpPage {
    sock: Socket,
    whole_fill: Duration,
    /// Origin of the top frame when first read: every later read must match.
    pinned: Option<String>,
    /// Top-frame fields and buttons of the last page context: the only
    /// nodes typed into or clicked.
    fields: HashSet<i64>,
    targets: HashSet<i64>,
    /// Fields of the last page context that text cannot fill (selects,
    /// checkboxes): `type_into` refuses them.
    untypable: HashSet<i64>,
}

/// The ASCII origin of `url`, `None` when opaque (about:, data:, file:).
fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    let o = u.origin();
    o.is_tuple().then(|| o.ascii_serialization())
}

struct Node {
    parent: Option<usize>,
    children: Vec<usize>,
    element: bool,
    /// Lowercase element name, `#text` for text.
    name: String,
    /// Text of a text node.
    text: String,
    attrs: Vec<(String, String)>,
    backend: i64,
    has_value: bool,
    checked: bool,
    rendered: bool,
}

impl Node {
    fn attr(&self, n: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.as_str())
    }
    fn attr_or_empty(&self, n: &str) -> &str {
        self.attr(n).unwrap_or("")
    }
}

struct Doc {
    nodes: Vec<Node>,
    title: String,
}

fn arr<'a>(v: &'a Value, k: &str) -> Result<&'a Vec<Value>, CdpError> {
    v.get(k).and_then(Value::as_array).ok_or(CdpError::Protocol)
}

fn string_at<'a>(strings: &'a [Value], i: &Value) -> &'a str {
    i.as_i64()
        .and_then(|i| usize::try_from(i).ok())
        .and_then(|i| strings.get(i))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// Node indices of a `RareStringData` whose string is not empty. The
/// strings themselves (field values) are never kept.
fn rare_nonempty(nodes: &Value, k: &str, strings: &[Value]) -> HashSet<usize> {
    let mut out = HashSet::new();
    let Some(r) = nodes.get(k) else { return out };
    let (Some(idx), Some(val)) = (
        r.get("index").and_then(Value::as_array),
        r.get("value").and_then(Value::as_array),
    ) else {
        return out;
    };
    for (i, v) in idx.iter().zip(val) {
        if let Some(i) = i.as_u64()
            && !string_at(strings, v).is_empty()
        {
            out.insert(i as usize);
        }
    }
    out
}

fn parse_doc(doc: &Value, strings: &[Value]) -> Result<Doc, CdpError> {
    let nodes = doc.get("nodes").ok_or(CdpError::Protocol)?;
    let parent = arr(nodes, "parentIndex")?;
    let ntype = arr(nodes, "nodeType")?;
    let nname = arr(nodes, "nodeName")?;
    let nvalue = arr(nodes, "nodeValue")?;
    let backend = arr(nodes, "backendNodeId")?;
    let attributes = arr(nodes, "attributes")?;
    let n = parent.len();
    if [
        ntype.len(),
        nname.len(),
        nvalue.len(),
        backend.len(),
        attributes.len(),
    ]
    .iter()
    .any(|l| *l != n)
    {
        return Err(CdpError::Protocol);
    }
    let mut has_value = rare_nonempty(nodes, "inputValue", strings);
    has_value.extend(rare_nonempty(nodes, "textValue", strings));
    let checked: HashSet<usize> = nodes
        .get("inputChecked")
        .and_then(|c| c.get("index"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_u64)
                .map(|i| i as usize)
                .collect()
        })
        .unwrap_or_default();
    let mut rendered = HashSet::new();
    if let Some(layout) = doc.get("layout") {
        let idx = arr(layout, "nodeIndex")?;
        let bounds = arr(layout, "bounds")?;
        let styles = arr(layout, "styles")?;
        for ((i, b), s) in idx.iter().zip(bounds).zip(styles) {
            let Some(i) = i.as_u64() else { continue };
            let b: Vec<f64> = b
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_f64).collect())
                .unwrap_or_default();
            let s: Vec<&str> = s
                .as_array()
                .map(|a| a.iter().map(|v| string_at(strings, v)).collect())
                .unwrap_or_default();
            let sized = b.len() == 4 && b[2] > 0.0 && b[3] > 0.0;
            let shown = s.first().is_none_or(|d| *d != "none")
                && s.get(1).is_none_or(|v| *v != "hidden" && *v != "collapse")
                && s.get(2)
                    .is_none_or(|o| o.parse::<f64>().map_or(true, |o| o > 0.0));
            if sized && shown {
                rendered.insert(i as usize);
            }
        }
    }
    let mut out: Vec<Node> = Vec::with_capacity(n);
    for i in 0..n {
        let element = ntype[i].as_i64() == Some(1);
        let name = string_at(strings, &nname[i]).to_ascii_lowercase();
        let mut attrs = Vec::new();
        // `value` is read only for button inputs (their label): on any
        // other control it is a server-rendered value, never kept.
        let button_input = name == "input"
            && attributes[i].as_array().is_some_and(|a| {
                a.chunks(2).any(|p| {
                    matches!(p, [k, v] if string_at(strings, k).eq_ignore_ascii_case("type")
                    && matches!(
                        string_at(strings, v).trim().to_ascii_lowercase().as_str(),
                        "submit" | "button" | "reset"
                    ))
                })
            });
        if element && let Some(a) = attributes[i].as_array() {
            for pair in a.chunks(2) {
                if let [k, v] = pair {
                    let k = string_at(strings, k).to_ascii_lowercase();
                    if KEPT_ATTRS.contains(&k.as_str()) && (k != "value" || button_input) {
                        let v: String = string_at(strings, v)
                            .chars()
                            .take(classify::MAX_SOURCE_CHARS)
                            .collect();
                        attrs.push((k, v));
                    }
                }
            }
        }
        let p = parent[i]
            .as_i64()
            .and_then(|p| usize::try_from(p).ok())
            .filter(|p| *p < i);
        out.push(Node {
            parent: p,
            children: vec![],
            element,
            text: if ntype[i].as_i64() == Some(3) {
                string_at(strings, &nvalue[i]).chars().take(400).collect()
            } else {
                String::new()
            },
            name,
            attrs,
            backend: backend[i].as_i64().ok_or(CdpError::Protocol)?,
            has_value: has_value.contains(&i),
            checked: checked.contains(&i),
            rendered: rendered.contains(&i),
        });
    }
    for i in 0..n {
        if let Some(p) = out[i].parent {
            out[p].children.push(i);
        }
    }
    Ok(Doc {
        nodes: out,
        title: doc
            .get("title")
            .map(|t| string_at(strings, t).to_owned())
            .unwrap_or_default(),
    })
}

/// Pre-order indices of the subtree under `root` (root included).
fn subtree(doc: &Doc, root: usize) -> Vec<usize> {
    let mut out = vec![];
    let mut stack = vec![root];
    while let Some(i) = stack.pop() {
        out.push(i);
        for c in doc.nodes[i].children.iter().rev() {
            stack.push(*c);
        }
    }
    out
}

const NON_TEXT: [&str; 6] = [
    "select", "option", "textarea", "script", "style", "template",
];

/// The extension's `ownText`: text nodes under `el`, joined by spaces,
/// without the text of nested controls, at most `max` characters.
fn own_text(doc: &Doc, el: usize, max: usize) -> String {
    let mut out = String::new();
    let mut stack = vec![el];
    while let Some(i) = stack.pop() {
        if out.chars().count() >= max {
            break;
        }
        let n = &doc.nodes[i];
        if i != el && NON_TEXT.contains(&n.name.as_str()) {
            continue;
        }
        if !n.element && n.name == "#text" {
            out.push(' ');
            out.push_str(&n.text);
        }
        for c in n.children.iter().rev() {
            stack.push(*c);
        }
    }
    out.chars().take(max).collect()
}

fn ancestors(doc: &Doc, i: usize) -> impl Iterator<Item = usize> + '_ {
    std::iter::successors(doc.nodes[i].parent, move |p| doc.nodes[*p].parent)
}

fn is_control(n: &Node) -> bool {
    matches!(n.name.as_str(), "input" | "select" | "textarea")
}

fn contains_control(doc: &Doc, i: usize) -> bool {
    subtree(doc, i).iter().any(|j| is_control(&doc.nodes[*j]))
}

fn prev_element_siblings(doc: &Doc, i: usize) -> Vec<usize> {
    let Some(p) = doc.nodes[i].parent else {
        return vec![];
    };
    let sibs = &doc.nodes[p].children;
    let pos = sibs.iter().position(|s| *s == i).unwrap_or(0);
    sibs[..pos]
        .iter()
        .rev()
        .copied()
        .filter(|s| doc.nodes[*s].element)
        .collect()
}

fn control_type(n: &Node) -> String {
    match n.name.as_str() {
        "select" => "select".into(),
        "textarea" => "textarea".into(),
        _ => {
            let t = n.attr_or_empty("type").trim().to_ascii_lowercase();
            if INPUT_TYPES.contains(&t.as_str()) {
                t
            } else {
                "text".into()
            }
        }
    }
}

fn is_field_candidate(n: &Node) -> bool {
    match n.name.as_str() {
        "select" | "textarea" => true,
        "input" => !NON_FIELD_TYPES.contains(&control_type(n).as_str()),
        _ => false,
    }
}

fn is_button(n: &Node) -> bool {
    if !n.element {
        return false;
    }
    let href = n.attr("href").map(|h| h.trim().to_ascii_lowercase());
    match n.name.as_str() {
        "button" => true,
        "input" => matches!(control_type(n).as_str(), "submit" | "image" | "button"),
        "a" => {
            n.attr("role") == Some("button")
                || href
                    .as_deref()
                    .is_none_or(|h| h.starts_with('#') || h.starts_with("javascript:"))
        }
        _ => n.attr("role") == Some("button"),
    }
}

fn is_submit_type(n: &Node) -> bool {
    match n.name.as_str() {
        "button" => {
            // A missing or unknown type is a submit.
            let t = n.attr_or_empty("type").trim().to_ascii_lowercase();
            !matches!(t.as_str(), "button" | "reset")
        }
        "input" => matches!(control_type(n).as_str(), "submit" | "image"),
        _ => false,
    }
}

fn button_label(doc: &Doc, i: usize) -> String {
    let n = &doc.nodes[i];
    if let Some(a) = n.attr("aria-label").filter(|a| !a.trim().is_empty()) {
        return a.to_owned();
    }
    let t = own_text(doc, i, 200);
    if !t.trim().is_empty() {
        return t;
    }
    if n.name == "input" {
        return n.attr_or_empty("value").to_owned();
    }
    String::new()
}

struct Group {
    /// The form element, or the closest common ancestor of loose fields.
    container: usize,
    is_form: bool,
    fields: Vec<usize>,
}

fn by_id(doc: &Doc) -> HashMap<&str, usize> {
    let mut m = HashMap::new();
    for (i, n) in doc.nodes.iter().enumerate() {
        if let Some(id) = n.attr("id").filter(|id| !id.is_empty()) {
            m.entry(id).or_insert(i);
        }
    }
    m
}

fn form_of(doc: &Doc, ids: &HashMap<&str, usize>, i: usize) -> Option<usize> {
    if let Some(f) = doc.nodes[i].attr("form")
        && let Some(&j) = ids.get(f)
        && doc.nodes[j].name == "form"
    {
        return Some(j);
    }
    ancestors(doc, i).find(|a| doc.nodes[*a].name == "form")
}

fn common_ancestor(doc: &Doc, items: &[usize]) -> usize {
    let first = items[0];
    let mut chain: Vec<usize> = std::iter::once(first)
        .chain(ancestors(doc, first))
        .collect();
    for &i in &items[1..] {
        let mine: HashSet<usize> = std::iter::once(i).chain(ancestors(doc, i)).collect();
        chain.retain(|c| mine.contains(c));
    }
    chain.first().copied().unwrap_or(0)
}

fn field_facts(
    doc: &Doc,
    ids: &HashMap<&str, usize>,
    labels: &HashMap<&str, Vec<usize>>,
    i: usize,
) -> FieldFacts {
    let n = &doc.nodes[i];
    let a = |k: &str| n.attr_or_empty(k).to_owned();
    let mut labelled = String::new();
    for id in n
        .attr_or_empty("aria-labelledby")
        .split_whitespace()
        .take(3)
    {
        if let Some(&j) = ids.get(id) {
            labelled.push(' ');
            labelled.push_str(&own_text(doc, j, 200));
        }
    }
    let mut label = String::new();
    let mut label_nodes: Vec<usize> = n
        .attr("id")
        .and_then(|id| labels.get(id))
        .cloned()
        .unwrap_or_default();
    if let Some(l) = ancestors(doc, i).find(|a| doc.nodes[*a].name == "label")
        && !label_nodes.contains(&l)
    {
        label_nodes.push(l);
    }
    for l in label_nodes.into_iter().take(3) {
        label.push(' ');
        label.push_str(&own_text(doc, l, 200));
    }
    let mut sibling = String::new();
    for s in prev_element_siblings(doc, i).into_iter().take(2) {
        if contains_control(doc, s) {
            break;
        }
        sibling = format!("{} {sibling}", own_text(doc, s, 100));
    }
    let nearby = if sibling.trim().is_empty() {
        n.parent
            .and_then(|p| prev_element_siblings(doc, p).first().copied())
            .filter(|b| !contains_control(doc, *b))
            .map(|b| own_text(doc, b, 100))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let inputmode = n.attr_or_empty("inputmode").to_ascii_lowercase();
    let pattern = n.attr_or_empty("pattern");
    FieldFacts {
        control_type: control_type(n),
        autocomplete: a("autocomplete"),
        sources: vec![
            (classify::W_NAME, a("name")),
            (classify::W_ID, a("id")),
            (classify::W_PLACEHOLDER, a("placeholder")),
            (classify::W_ARIA, format!("{} {labelled}", a("aria-label"))),
            (classify::W_LABEL, label),
            (classify::W_TITLE, a("title")),
            (classify::W_SIBLING, sibling),
            (classify::W_NEARBY, nearby),
        ],
        max_length: n.attr_or_empty("maxlength").trim().parse().ok(),
        numeric: n.name == "input" && (inputmode == "numeric" || inputmode == "decimal"),
        digit_pattern: pattern.starts_with("\\d") || pattern.starts_with("[0-9]"),
    }
}

fn visible(n: &Node) -> bool {
    if n.attr("readonly").is_some() && n.name != "select" {
        return false;
    }
    n.attr("disabled").is_none() && n.rendered
}

fn prefilled(n: &Node, control: &str) -> Prefilled {
    let holds = match control {
        "checkbox" => n.checked,
        // A select's chosen option is not read: always empty here.
        "select" => false,
        _ => n.has_value,
    };
    if holds {
        Prefilled::Typed
    } else {
        Prefilled::Empty
    }
}

const NEWSLETTER_ROLES: [FieldRole; 5] = [
    FieldRole::Email,
    FieldRole::GivenName,
    FieldRole::FamilyName,
    FieldRole::FullName,
    FieldRole::RememberMe,
];

/// The page context of the top document, as `buildPageContext` makes it.
/// Returns it with the backend ids of its fields and buttons.
fn build_context(doc: &Doc, origin: &str, url: &str) -> (PageContext, HashSet<i64>, HashSet<i64>) {
    let ids = by_id(doc);
    let mut labels: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, n) in doc.nodes.iter().enumerate() {
        if n.name == "label"
            && let Some(f) = n.attr("for").filter(|f| !f.is_empty())
        {
            labels.entry(f).or_default().push(i);
        }
    }
    // Groups in order of their first field.
    let mut groups: Vec<Group> = vec![];
    let mut loose: Vec<usize> = vec![];
    let mut loose_at: Option<usize> = None;
    for (i, n) in doc.nodes.iter().enumerate() {
        if !n.element || !is_field_candidate(n) {
            continue;
        }
        match form_of(doc, &ids, i) {
            Some(f) => match groups.iter_mut().find(|g| g.is_form && g.container == f) {
                Some(g) => g.fields.push(i),
                None => groups.push(Group {
                    container: f,
                    is_form: true,
                    fields: vec![i],
                }),
            },
            None => {
                if loose_at.is_none() {
                    loose_at = Some(groups.len());
                    groups.push(Group {
                        container: 0,
                        is_form: false,
                        fields: vec![],
                    });
                }
                loose.push(i);
            }
        }
    }
    if let Some(at) = loose_at {
        groups[at].container = common_ancestor(doc, &loose);
        groups[at].fields = loose;
    }
    groups.truncate(MAX_FORMS);

    let in_form: HashSet<usize> = doc
        .nodes
        .iter()
        .enumerate()
        .filter(|(i, _)| ancestors(doc, *i).any(|a| doc.nodes[a].name == "form"))
        .map(|(i, _)| i)
        .collect();
    let mut page_words = String::new();
    if groups.len() == 1 {
        let h1 = doc.nodes.iter().position(|n| n.name == "h1");
        let path = url::Url::parse(url)
            .map(|u| u.path().to_owned())
            .unwrap_or_default();
        page_words = [
            classify::normalize(&doc.title),
            h1.map(|h| classify::normalize(&own_text(doc, h, 100)))
                .unwrap_or_default(),
            classify::normalize(&path),
        ]
        .join(" ");
    }

    let mut field_ids = HashSet::new();
    let mut button_ids = HashSet::new();
    let mut forms = vec![];
    for g in &groups {
        // Roles first with "a card form", then again for a lone security code.
        let facts: Vec<FieldFacts> = g
            .fields
            .iter()
            .take(MAX_FIELDS)
            .map(|i| field_facts(doc, &ids, &labels, *i))
            .collect();
        let first: Vec<(FieldRole, f32)> =
            facts.iter().map(|f| classify::classify(f, true)).collect();
        let card_form = first.iter().any(|(r, _)| {
            matches!(
                r,
                FieldRole::CcName
                    | FieldRole::CcNumber
                    | FieldRole::CcExp
                    | FieldRole::CcExpMonth
                    | FieldRole::CcExpYear
            )
        });
        let roles: Vec<(FieldRole, f32)> = if card_form {
            first
        } else {
            facts.iter().map(|f| classify::classify(f, false)).collect()
        };
        let mut fields = vec![];
        for ((i, f), (role, confidence)) in g.fields.iter().zip(&facts).zip(&roles) {
            let n = &doc.nodes[*i];
            field_ids.insert(n.backend);
            fields.push(FieldContext {
                field_ref: n.backend.to_string(),
                role: Some(*role),
                confidence: *confidence,
                visible: visible(n),
                prefilled: prefilled(n, &f.control_type),
            });
        }

        // Buttons: in the container (and outside any form for loose
        // fields), plus `form="id"` buttons of a form.
        let form_id = if g.is_form {
            doc.nodes[g.container].attr("id").filter(|i| !i.is_empty())
        } else {
            None
        };
        let mut cands: Vec<usize> = subtree(doc, g.container)
            .into_iter()
            .filter(|b| is_button(&doc.nodes[*b]))
            .filter(|b| {
                if g.is_form {
                    form_of(doc, &ids, *b) == Some(g.container)
                } else {
                    !in_form.contains(b)
                }
            })
            .collect();
        if let Some(fid) = form_id {
            for (b, n) in doc.nodes.iter().enumerate() {
                if n.attr("form") == Some(fid) && is_button(n) && !cands.contains(&b) {
                    cands.push(b);
                }
            }
            cands.sort_unstable();
        }
        let kept: Vec<(usize, String, ButtonClass)> = cands
            .into_iter()
            .filter(|b| {
                let n = &doc.nodes[*b];
                n.attr("disabled").is_none() && n.rendered
            })
            .map(|b| {
                let label = classify::normalize(&button_label(doc, b));
                let class = classify::button_class(&label, is_submit_type(&doc.nodes[b]));
                (b, label, class)
            })
            .collect();
        // The submit the detector would pick: the first submit-class button.
        let submit = kept
            .iter()
            .find(|(_, _, c)| *c == ButtonClass::Submit)
            .map(|(b, _, _)| *b);
        let rank = |b: usize, c: ButtonClass| -> u8 {
            if Some(b) == submit {
                0
            } else if matches!(
                c,
                ButtonClass::Pay | ButtonClass::Create | ButtonClass::Passkey
            ) {
                1
            } else {
                2
            }
        };
        let mut ranked = kept;
        ranked.sort_by_key(|(b, _, c)| rank(*b, *c));
        ranked.truncate(MAX_BUTTONS);

        // Intent hints from the form's own words (and the page's when alone).
        let c = &doc.nodes[g.container];
        let mut words: Vec<String> = ["aria-label", "id", "name", "action", "role"]
            .iter()
            .map(|a| classify::normalize(c.attr_or_empty(a)))
            .collect();
        for h in subtree(doc, g.container)
            .into_iter()
            .filter(|h| {
                matches!(
                    doc.nodes[*h].name.as_str(),
                    "h1" | "h2" | "h3" | "h4" | "legend"
                )
            })
            .take(MAX_FORM_HEADINGS)
        {
            words.push(classify::normalize(&own_text(doc, h, 100)));
        }
        words.extend(ranked.iter().map(|(_, l, _)| l.clone()));
        let words = words.join(" ");
        let all = format!("{words} {page_words}");
        let role_list: Vec<FieldRole> = fields.iter().filter_map(|f| f.role).collect();
        let secret = role_list.iter().any(|r| {
            matches!(
                r,
                FieldRole::CurrentPassword
                    | FieldRole::NewPassword
                    | FieldRole::ConfirmPassword
                    | FieldRole::Otp
            )
        });
        let search = c
            .attr("role")
            .is_some_and(|r| r.eq_ignore_ascii_case("search"))
            || subtree(doc, g.container).iter().any(|i| {
                let n = &doc.nodes[*i];
                (n.name == "input" && n.attr_or_empty("type").eq_ignore_ascii_case("search"))
                    || n.attr("role") == Some("searchbox")
            })
            || classify::search_words(&words);
        let newsletter = !role_list.is_empty()
            && role_list.iter().all(|r| NEWSLETTER_ROLES.contains(r))
            && classify::newsletter_words(&words);

        for (b, _, _) in &ranked {
            button_ids.insert(doc.nodes[*b].backend);
        }
        forms.push(FormContext {
            form_ref: if g.is_form {
                c.backend.to_string()
            } else {
                "page".into()
            },
            intent_hints: IntentHints {
                kind: None,
                signup_words: classify::signup_words(&all),
                reset_words: classify::reset_words(&all),
                checkout_words: classify::checkout_words(&all),
                ignore: !secret && (search || newsletter),
            },
            step_index: None,
            fields,
            buttons: ranked
                .iter()
                .map(|(b, _, class)| ButtonContext {
                    button_ref: doc.nodes[*b].backend.to_string(),
                    class: *class,
                })
                .collect(),
        });
    }
    let ctx = PageContext {
        origin: origin.to_owned(),
        top_origin: origin.to_owned(),
        frame_kind: FrameKind::Top,
        forms,
        typed_username_hash: None,
    };
    (ctx, field_ids, button_ids)
}

impl CdpPage {
    pub(crate) fn new(sock: Socket, whole_fill: Duration) -> Self {
        CdpPage {
            sock,
            whole_fill,
            pinned: None,
            fields: HashSet::new(),
            targets: HashSet::new(),
            untypable: HashSet::new(),
        }
    }

    pub(crate) fn whole_fill(&self) -> Duration {
        self.whole_fill
    }

    pub(crate) fn socket(&mut self) -> &mut Socket {
        &mut self.sock
    }

    /// The top frame's id, loader id (new for every document) and URL
    /// (`Page.getFrameTree`).
    fn frame(&mut self) -> Result<(String, String, String), CdpError> {
        let r = self.sock.call("Page.getFrameTree", json!({}))?;
        let f = &r["frameTree"]["frame"];
        let field = |k: &str| f[k].as_str().map(str::to_owned).ok_or(CdpError::Protocol);
        Ok((field("id")?, field("loaderId")?, field("url")?))
    }

    /// Reads the top frame and holds its origin to the first one read.
    /// Returns the frame id, the loader id, the URL and the origin.
    fn checked_frame(&mut self) -> Result<(String, String, String, String), CdpError> {
        let (id, loader, url) = self.frame()?;
        let origin = origin_of(&url).ok_or(CdpError::OriginChanged)?;
        match &self.pinned {
            None => self.pinned = Some(origin.clone()),
            Some(p) if *p != origin => return Err(CdpError::OriginChanged),
            Some(_) => {}
        }
        Ok((id, loader, url, origin))
    }

    /// The origin pinned by the first read of the top frame.
    pub fn pinned_origin(&self) -> Option<&str> {
        self.pinned.as_deref()
    }

    /// The real URL of the top frame, as Chrome reports it (no fragment).
    /// The first call pins its origin for every later step; this call
    /// itself never fails on a changed origin.
    pub fn main_frame_url(&mut self) -> Result<String, CdpError> {
        let (_, _, url) = self.frame()?;
        if self.pinned.is_none() {
            self.pinned = origin_of(&url);
        }
        Ok(url)
    }

    /// The page title (`Target.getTargetInfo`).
    pub fn title(&mut self) -> Result<String, CdpError> {
        let r = self.sock.call("Target.getTargetInfo", json!({}))?;
        r["targetInfo"]["title"]
            .as_str()
            .map(|t| t.chars().take(512).collect())
            .ok_or(CdpError::Protocol)
    }

    /// The top frame's forms for `fill_plan::plan`, from
    /// `DOMSnapshot.captureSnapshot`. Sub-frames are left out. Refs are
    /// backend node ids. [`CdpError::NoFields`] when the top frame holds no
    /// field; [`CdpError::OriginChanged`] when the origin moved.
    pub fn page_context(&mut self) -> Result<PageContext, CdpError> {
        let (frame_id, loader, url, origin) = self.checked_frame()?;
        let snap = self.sock.call(
            "DOMSnapshot.captureSnapshot",
            json!({"computedStyles": STYLES}),
        )?;
        let strings = arr(&snap, "strings")?;
        let top = arr(&snap, "documents")?
            .iter()
            .find(|d| d.get("frameId").map(|f| string_at(strings, f)) == Some(frame_id.as_str()))
            .ok_or(CdpError::Protocol)?;
        let doc = parse_doc(top, strings)?;
        drop(snap);
        // The page may have moved while it was read: another origin, or
        // another document (a new loader id, even on the same origin), and
        // the snapshot's node ids are stale.
        let (_, loader_after, _, _) = self.checked_frame()?;
        if loader_after != loader {
            return Err(CdpError::OriginChanged);
        }
        let (ctx, fields, targets) = build_context(&doc, &origin, &url);
        if fields.is_empty() {
            return Err(CdpError::NoFields);
        }
        ctx.validate().map_err(|_| CdpError::Protocol)?;
        self.untypable = doc
            .nodes
            .iter()
            .filter(|n| fields.contains(&n.backend))
            .filter(|n| matches!(control_type(n).as_str(), "select" | "checkbox"))
            .map(|n| n.backend)
            .collect();
        self.fields = fields;
        self.targets = targets;
        Ok(ctx)
    }

    /// Whether `type_into` can fill this field of the last page context:
    /// [`CdpError::Unsupported`] for a select or a checkbox, which text
    /// cannot set, [`CdpError::Protocol`] for a node not in that context.
    pub fn check_typable(&self, backend_node_id: i64) -> Result<(), CdpError> {
        if !self.fields.contains(&backend_node_id) {
            return Err(CdpError::Protocol);
        }
        if self.untypable.contains(&backend_node_id) {
            return Err(CdpError::Unsupported);
        }
        Ok(())
    }

    /// Types `value` into a field of the last page context, replacing what
    /// it holds: the top frame's origin is read again first, then
    /// `DOM.focus`, a select-all (`Input.dispatchKeyEvent` Meta+A then
    /// Control+A, each with the `selectAll` editing command), the origin
    /// once more (a focus or key handler can navigate), then
    /// `Input.insertText`, which replaces the selection.
    /// See [`CdpPage::check_typable`] for the fields it refuses.
    pub fn type_into(&mut self, backend_node_id: i64, value: &str) -> Result<(), CdpError> {
        self.check_typable(backend_node_id)?;
        self.checked_frame()?;
        self.sock
            .call("DOM.focus", json!({"backendNodeId": backend_node_id}))?;
        // Meta is 4, Control is 2 (`Input.dispatchKeyEvent` modifiers).
        for modifiers in [4, 2] {
            for kind in ["keyDown", "keyUp"] {
                let mut p = json!({"type": kind, "modifiers": modifiers, "key": "a",
                    "code": "KeyA", "windowsVirtualKeyCode": 65});
                if kind == "keyDown" {
                    p["commands"] = json!(["selectAll"]);
                }
                self.sock.call("Input.dispatchKeyEvent", p)?;
            }
        }
        self.checked_frame()?;
        self.sock.insert_text(value)
    }

    /// Clicks a button (or field) of the last page context at the centre of
    /// its box, after the same origin check.
    pub fn click(&mut self, backend_node_id: i64) -> Result<(), CdpError> {
        if !self.targets.contains(&backend_node_id) && !self.fields.contains(&backend_node_id) {
            return Err(CdpError::Protocol);
        }
        self.checked_frame()?;
        self.sock.call(
            "DOM.scrollIntoViewIfNeeded",
            json!({"backendNodeId": backend_node_id}),
        )?;
        let r = self
            .sock
            .call("DOM.getBoxModel", json!({"backendNodeId": backend_node_id}))?;
        let q: Vec<f64> = r["model"]["content"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_f64).collect())
            .unwrap_or_default();
        if q.len() != 8 {
            return Err(CdpError::Protocol);
        }
        let x = (q[0] + q[2] + q[4] + q[6]) / 4.0;
        let y = (q[1] + q[3] + q[5] + q[7]) / 4.0;
        self.sock.call(
            "Input.dispatchMouseEvent",
            json!({"type": "mouseMoved", "x": x, "y": y}),
        )?;
        for (kind, buttons) in [("mousePressed", 1), ("mouseReleased", 0)] {
            self.sock.call(
                "Input.dispatchMouseEvent",
                json!({"type": kind, "x": x, "y": y, "button": "left",
                       "buttons": buttons, "clickCount": 1}),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeDocument, el, snapshot, text};

    #[test]
    fn value_attribute_is_kept_for_button_inputs_only() {
        let doc = FakeDocument {
            url: "https://example.com/".into(),
            title: "t".into(),
            frame_id: "MAIN".into(),
            root: el(
                "form",
                &[],
                vec![
                    el(
                        "input",
                        &[("value", "server-secret"), ("type", "password")],
                        vec![],
                    )
                    .id(1),
                    el("input", &[("type", "text"), ("value", "prefill")], vec![]).id(2),
                    el("input", &[("type", "SUBMIT"), ("value", "Log in")], vec![]).id(3),
                    el("button", &[("value", "x")], vec![text("Go")]).id(4),
                ],
            ),
        };
        let snap = snapshot(&[doc]);
        let strings = snap["strings"].as_array().unwrap();
        let d = parse_doc(&snap["documents"][0], strings).unwrap();
        let node = |id: i64| d.nodes.iter().find(|n| n.backend == id).unwrap();
        assert_eq!(node(1).attr("value"), None);
        assert_eq!(node(1).attr("type"), Some("password"));
        assert_eq!(node(2).attr("value"), None);
        assert_eq!(node(3).attr("value"), Some("Log in"));
        assert_eq!(node(4).attr("value"), None);
        for n in &d.nodes {
            assert!(n.attrs.iter().all(|(_, v)| v != "server-secret"));
            assert!(n.text != "server-secret");
        }
    }
}
