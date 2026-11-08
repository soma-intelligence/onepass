//! A fake DevTools page server on 127.0.0.1 for tests (feature `testing`).
//! It answers the commands this crate sends from a scripted page and
//! records every command it receives.

use std::collections::{HashMap, HashSet};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{Value, json};
use tungstenite::Message;

/// One node of a fake document: an element or a text node.
#[derive(Debug, Clone)]
pub struct FakeNode {
    name: String,
    text: Option<String>,
    attrs: Vec<(String, String)>,
    children: Vec<FakeNode>,
    backend_id: Option<i64>,
    /// x, y, width, height. `None`: no layout box (display none).
    bounds: Option<[f64; 4]>,
    visibility: String,
    value: String,
    checked: bool,
}

/// An element, rendered at 0,0 with a 100 by 20 box.
pub fn el(name: &str, attrs: &[(&str, &str)], children: Vec<FakeNode>) -> FakeNode {
    FakeNode {
        name: name.to_ascii_uppercase(),
        text: None,
        attrs: attrs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        children,
        backend_id: None,
        bounds: Some([0.0, 0.0, 100.0, 20.0]),
        visibility: "visible".into(),
        value: String::new(),
        checked: false,
    }
}

/// A text node.
pub fn text(s: &str) -> FakeNode {
    FakeNode {
        name: "#text".into(),
        text: Some(s.to_owned()),
        attrs: vec![],
        children: vec![],
        backend_id: None,
        bounds: None,
        visibility: "visible".into(),
        value: String::new(),
        checked: false,
    }
}

impl FakeNode {
    /// Gives the node this `backendNodeId` (others get one from 10000 up).
    pub fn id(mut self, backend_id: i64) -> Self {
        self.backend_id = Some(backend_id);
        self
    }

    /// No layout box, as `display: none`.
    pub fn not_rendered(mut self) -> Self {
        self.bounds = None;
        self
    }

    /// `visibility: hidden`.
    pub fn invisible(mut self) -> Self {
        self.visibility = "hidden".into();
        self
    }

    /// The layout box.
    pub fn at(mut self, x: f64, y: f64, w: f64, h: f64) -> Self {
        self.bounds = Some([x, y, w, h]);
        self
    }

    /// The control's current value (`inputValue` in the snapshot).
    pub fn with_value(mut self, v: &str) -> Self {
        self.value = v.to_owned();
        self
    }

    pub fn checked(mut self) -> Self {
        self.checked = true;
        self
    }
}

/// One document of the snapshot, the frame that holds it.
#[derive(Debug, Clone)]
pub struct FakeDocument {
    pub url: String,
    pub title: String,
    pub frame_id: String,
    pub root: FakeNode,
}

/// A plain login page at `url`: user field 11, password 12, submit 13,
/// one hidden input, an unrendered field and a cross-origin iframe document
/// that also holds a password field (21).
pub fn login_page(url: &str) -> Vec<FakeDocument> {
    let form = el(
        "form",
        &[("id", "login"), ("action", "/session")],
        vec![
            el("h2", &[], vec![text("Sign in")]),
            el("label", &[("for", "user")], vec![text("Email")]),
            el(
                "input",
                &[
                    ("id", "user"),
                    ("type", "email"),
                    ("name", "email"),
                    ("autocomplete", "username"),
                ],
                vec![],
            )
            .id(11)
            .at(10.0, 40.0, 200.0, 24.0),
            el("label", &[("for", "pw")], vec![text("Password")]),
            el(
                "input",
                &[("id", "pw"), ("type", "password"), ("name", "password")],
                vec![],
            )
            .id(12)
            .at(10.0, 80.0, 200.0, 24.0),
            el("input", &[("type", "hidden"), ("name", "csrf")], vec![])
                .with_value("token")
                .not_rendered(),
            el("input", &[("type", "text"), ("name", "honeypot")], vec![])
                .id(14)
                .not_rendered(),
            el("button", &[("type", "submit")], vec![text("Sign in")])
                .id(13)
                .at(10.0, 120.0, 80.0, 30.0),
        ],
    );
    let top = FakeDocument {
        url: url.to_owned(),
        title: "Example sign in".into(),
        frame_id: "MAIN".into(),
        root: el(
            "html",
            &[],
            vec![el(
                "body",
                &[],
                vec![
                    form,
                    el("iframe", &[("src", "https://ads.example.net/")], vec![]),
                ],
            )],
        ),
    };
    let child = FakeDocument {
        url: "https://ads.example.net/".into(),
        title: "ad".into(),
        frame_id: "CHILD".into(),
        root: el(
            "html",
            &[],
            vec![el(
                "body",
                &[],
                vec![
                    el(
                        "input",
                        &[("type", "password"), ("name", "password")],
                        vec![],
                    )
                    .id(21),
                ],
            )],
        ),
    };
    vec![top, child]
}

/// A checkout page at `url`: card number 31, holder 32, expiry 33, code
/// 34 (labels only, no autocomplete), and a "Pay now" button 35.
pub fn card_page(url: &str) -> Vec<FakeDocument> {
    let row = |label: &str, name: &str, id: i64| {
        el(
            "div",
            &[],
            vec![
                el("span", &[], vec![text(label)]),
                el("input", &[("type", "text"), ("name", name)], vec![]).id(id),
            ],
        )
    };
    let form = el(
        "form",
        &[("id", "pay"), ("action", "/checkout")],
        vec![
            el("h2", &[], vec![text("Payment")]),
            row("Card number", "f1", 31),
            row("Name on card", "f2", 32),
            row("Expiry (MM/YY)", "f3", 33),
            row("Security code", "f4", 34),
            el("button", &[("type", "submit")], vec![text("Pay now")]).id(35),
        ],
    );
    vec![FakeDocument {
        url: url.to_owned(),
        title: "Checkout".into(),
        frame_id: "MAIN".into(),
        root: el("html", &[], vec![el("body", &[], vec![form])]),
    }]
}

/// The checkout of [`card_page`] with the expiry as a select (33) instead
/// of a text field.
pub fn card_page_with_select(url: &str) -> Vec<FakeDocument> {
    let mut docs = card_page(url);
    let form = &mut docs[0].root.children[0].children[0];
    let row = &mut form.children[3];
    row.children[1] = el(
        "select",
        &[("name", "f3")],
        vec![
            el("option", &[("value", "01")], vec![text("01")]),
            el("option", &[("value", "02")], vec![text("02")]),
        ],
    )
    .id(33);
    docs
}

/// Sets the current value of the node with `backend_id` in `docs`.
pub fn set_value(docs: &mut [FakeDocument], backend_id: i64, value: &str) {
    fn walk(n: &mut FakeNode, id: i64, v: &str) {
        if n.backend_id == Some(id) {
            n.value = v.to_owned();
        }
        for c in &mut n.children {
            walk(c, id, v);
        }
    }
    for d in docs {
        walk(&mut d.root, backend_id, value);
    }
}

/// A `DOMSnapshot.captureSnapshot` result for these documents, with
/// `computedStyles: ["display", "visibility", "opacity"]`.
pub fn snapshot(docs: &[FakeDocument]) -> Value {
    let mut strings: Vec<String> = Vec::new();
    let idx = |s: &str, strings: &mut Vec<String>| -> i64 {
        if let Some(i) = strings.iter().position(|x| x == s) {
            return i as i64;
        }
        strings.push(s.to_owned());
        (strings.len() - 1) as i64
    };
    let mut next_auto = 10_000i64;
    let mut out_docs = Vec::new();
    for d in docs {
        let mut parent = Vec::new();
        let mut node_type = Vec::new();
        let mut node_name = Vec::new();
        let mut node_value = Vec::new();
        let mut backend = Vec::new();
        let mut attributes = Vec::new();
        let mut input_idx = Vec::new();
        let mut input_val = Vec::new();
        let mut checked = Vec::new();
        let mut l_node = Vec::new();
        let mut l_styles = Vec::new();
        let mut l_bounds = Vec::new();
        let mut l_text = Vec::new();
        let mut stack: Vec<(&FakeNode, i64)> = vec![(&d.root, -1)];
        // Pre-order, children in document order.
        while let Some((n, p)) = stack.pop() {
            let i = parent.len() as i64;
            parent.push(p);
            let is_text = n.text.is_some();
            node_type.push(if is_text { 3 } else { 1 });
            node_name.push(idx(&n.name, &mut strings));
            node_value.push(idx(n.text.as_deref().unwrap_or(""), &mut strings));
            let id = n.backend_id.unwrap_or_else(|| {
                next_auto += 1;
                next_auto
            });
            backend.push(id);
            let mut a = Vec::new();
            for (k, v) in &n.attrs {
                a.push(idx(k, &mut strings));
                a.push(idx(v, &mut strings));
            }
            attributes.push(a);
            if n.name == "INPUT" || n.name == "TEXTAREA" {
                input_idx.push(i);
                input_val.push(idx(&n.value, &mut strings));
            }
            if n.checked {
                checked.push(i);
            }
            if let Some(b) = n.bounds {
                l_node.push(i);
                l_styles.push(vec![
                    idx("block", &mut strings),
                    idx(&n.visibility, &mut strings),
                    idx("1", &mut strings),
                ]);
                l_bounds.push(b.to_vec());
                l_text.push(-1);
            }
            for c in n.children.iter().rev() {
                stack.push((c, i));
            }
        }
        out_docs.push(json!({
            "documentURL": idx(&d.url, &mut strings),
            "title": idx(&d.title, &mut strings),
            "baseURL": idx(&d.url, &mut strings),
            "frameId": idx(&d.frame_id, &mut strings),
            "nodes": {
                "parentIndex": parent,
                "nodeType": node_type,
                "nodeName": node_name,
                "nodeValue": node_value,
                "backendNodeId": backend,
                "attributes": attributes,
                "inputValue": {"index": input_idx, "value": input_val},
                "inputChecked": {"index": checked},
            },
            "layout": {
                "nodeIndex": l_node,
                "styles": l_styles,
                "bounds": l_bounds,
                "text": l_text,
                "stackingContexts": {"index": []},
            },
            "textBoxes": {"layoutIndex": [], "bounds": [], "start": [], "length": []},
        }));
    }
    json!({"documents": out_docs, "strings": strings})
}

struct Shared {
    url: String,
    title: String,
    docs: Vec<FakeDocument>,
    log: Vec<Value>,
    inserts: usize,
    navigate_after: Option<(usize, String)>,
    navigate_on_focus: Option<String>,
    silent: HashSet<String>,
    /// Bumped on every navigation, as Chrome's loader id.
    loader: u64,
    /// Text of each control with a backend id, as typing leaves it.
    values: HashMap<i64, String>,
    focused: Option<i64>,
    selected: bool,
}

impl Shared {
    fn go(&mut self, url: String) {
        self.url = url;
        self.loader += 1;
    }
}

fn collect_values(n: &FakeNode, out: &mut HashMap<i64, String>) {
    if let Some(id) = n.backend_id {
        out.insert(id, n.value.clone());
    }
    for c in &n.children {
        collect_values(c, out);
    }
}

/// The fake server. Accepts any number of connections, one thread each.
pub struct FakeCdp {
    port: u16,
    shared: Arc<Mutex<Shared>>,
}

fn find_bounds(n: &FakeNode, id: i64) -> Option<Option<[f64; 4]>> {
    if n.backend_id == Some(id) {
        return Some(n.bounds);
    }
    n.children.iter().find_map(|c| find_bounds(c, id))
}

fn answer(shared: &Mutex<Shared>, method: &str, params: &Value) -> Option<Result<Value, String>> {
    let mut s = shared.lock().unwrap();
    if s.silent.contains(method) {
        return None;
    }
    Some(match method {
        "Page.getFrameTree" => {
            let mut children = vec![];
            for d in s.docs.iter().filter(|d| d.frame_id != "MAIN") {
                children.push(json!({"frame": {"id": d.frame_id, "parentId": "MAIN",
                    "loaderId": "L", "url": d.url, "mimeType": "text/html"}}));
            }
            Ok(json!({"frameTree": {
                "frame": {"id": "MAIN", "loaderId": format!("L{}", s.loader), "url": s.url,
                    "mimeType": "text/html"},
                "childFrames": children,
            }}))
        }
        "Target.getTargetInfo" => Ok(json!({"targetInfo": {
            "targetId": "FAKE", "type": "page", "title": s.title, "url": s.url,
            "attached": true, "canAccessOpener": false,
        }})),
        "DOMSnapshot.captureSnapshot" => Ok(snapshot(&s.docs)),
        "DOM.focus" => {
            s.focused = params.get("backendNodeId").and_then(Value::as_i64);
            s.selected = false;
            if let Some(url) = s.navigate_on_focus.take() {
                s.go(url);
            }
            Ok(json!({}))
        }
        "DOM.scrollIntoViewIfNeeded" | "Input.dispatchMouseEvent" => Ok(json!({})),
        "Input.dispatchKeyEvent" => {
            let select_all = params["commands"]
                .as_array()
                .is_some_and(|c| c.iter().any(|c| c == "selectAll"));
            if params["type"] == "keyDown" && select_all {
                s.selected = true;
            }
            Ok(json!({}))
        }
        "Input.insertText" => {
            s.inserts += 1;
            let text = params["text"].as_str().unwrap_or("").to_owned();
            let selected = std::mem::take(&mut s.selected);
            if let Some(id) = s.focused {
                let v = s.values.entry(id).or_default();
                if selected {
                    v.clear();
                }
                v.push_str(&text);
            }
            if let Some((n, url)) = s.navigate_after.clone()
                && s.inserts >= n
            {
                s.navigate_after = None;
                s.go(url);
            }
            Ok(json!({}))
        }
        "DOM.getBoxModel" => {
            let id = params.get("backendNodeId").and_then(Value::as_i64);
            let b = id.and_then(|id| {
                s.docs
                    .iter()
                    .find_map(|d| find_bounds(&d.root, id))
                    .flatten()
            });
            match b {
                Some([x, y, w, h]) => {
                    let quad = json!([x, y, x + w, y, x + w, y + h, x, y + h]);
                    Ok(
                        json!({"model": {"content": quad, "padding": quad, "border": quad,
                        "margin": quad, "width": w, "height": h}}),
                    )
                }
                None => Err("Could not compute box model.".into()),
            }
        }
        _ => Err(format!("'{method}' wasn't found")),
    })
}

impl FakeCdp {
    /// Serves a page at `url` (the top frame's URL) titled `title`, whose
    /// snapshot is `docs`. The top document's `frame_id` must be `MAIN`.
    pub fn start(url: &str, title: &str, docs: Vec<FakeDocument>) -> FakeCdp {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut values = HashMap::new();
        for d in &docs {
            collect_values(&d.root, &mut values);
        }
        let shared = Arc::new(Mutex::new(Shared {
            url: url.to_owned(),
            title: title.to_owned(),
            docs,
            log: vec![],
            inserts: 0,
            navigate_after: None,
            navigate_on_focus: None,
            silent: HashSet::new(),
            loader: 0,
            values,
            focused: None,
            selected: false,
        }));
        let sh = shared.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let sh = sh.clone();
                thread::spawn(move || {
                    let Ok(mut ws) = tungstenite::accept(stream) else {
                        return;
                    };
                    while let Ok(msg) = ws.read() {
                        let Message::Text(t) = msg else { continue };
                        let Ok(v) = serde_json::from_str::<Value>(t.as_str()) else {
                            continue;
                        };
                        let id = v.get("id").cloned().unwrap_or(Value::Null);
                        let method = v
                            .get("method")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        let params = v.get("params").cloned().unwrap_or(json!({}));
                        sh.lock()
                            .unwrap()
                            .log
                            .push(json!({"method": method, "params": params}));
                        // An event first, as Chrome may send one at any time.
                        let _ = ws.send(Message::text(
                            json!({"method": "Page.frameNavigated", "params": {}}).to_string(),
                        ));
                        let reply = match answer(&sh, &method, &params) {
                            None => continue,
                            Some(Ok(r)) => json!({"id": id, "result": r}),
                            Some(Err(m)) => {
                                json!({"id": id, "error": {"code": -32000, "message": m}})
                            }
                        };
                        if ws.send(Message::text(reply.to_string())).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        FakeCdp { port, shared }
    }

    /// The page's DevTools address.
    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}/devtools/page/FAKE", self.port)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Every command received, as `{"method": ..., "params": ...}`, in order.
    pub fn commands(&self) -> Vec<Value> {
        self.shared.lock().unwrap().log.clone()
    }

    /// Method names of [`FakeCdp::commands`].
    pub fn methods(&self) -> Vec<String> {
        self.commands()
            .iter()
            .map(|c| c["method"].as_str().unwrap_or("").to_owned())
            .collect()
    }

    /// The texts `Input.insertText` received, in order.
    pub fn inserted(&self) -> Vec<String> {
        self.commands()
            .iter()
            .filter(|c| c["method"] == "Input.insertText")
            .map(|c| c["params"]["text"].as_str().unwrap_or("").to_owned())
            .collect()
    }

    /// The top frame moves to `url` once `n` texts were inserted.
    pub fn navigate_after_inserts(&self, n: usize, url: &str) {
        self.shared.lock().unwrap().navigate_after = Some((n, url.to_owned()));
    }

    /// The top frame moves to `url` now.
    pub fn navigate(&self, url: &str) {
        self.shared.lock().unwrap().go(url.to_owned());
    }

    /// The top frame moves to `url` on the next `DOM.focus`.
    pub fn navigate_on_focus(&self, url: &str) {
        self.shared.lock().unwrap().navigate_on_focus = Some(url.to_owned());
    }

    /// The text a control holds now: its initial value, then what typing
    /// did to it (a select-all then insert replaces, an insert alone appends).
    pub fn field_text(&self, backend_id: i64) -> Option<String> {
        self.shared.lock().unwrap().values.get(&backend_id).cloned()
    }

    /// `method` is never answered.
    pub fn never_answer(&self, method: &str) {
        self.shared.lock().unwrap().silent.insert(method.to_owned());
    }
}
