//! `robots.txt` reader (RFC 9309): groups by user agent, longest match wins,
//! `Allow` wins a tie, `*` and `$` wildcards. The bench reads the groups for
//! its own token (`OnePassBench`) and falls back to `*`.

/// Product token the bench looks for in `robots.txt`.
pub const AGENT: &str = "OnePassBench";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    allow: bool,
    pattern: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Group {
    agents: Vec<String>,
    rules: Vec<Rule>,
}

/// A parsed `robots.txt`. An empty or unreadable file allows everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Robots {
    groups: Vec<Group>,
}

impl Robots {
    pub fn parse(text: &str) -> Robots {
        let mut groups: Vec<Group> = Vec::new();
        // A run of User-agent lines opens one group; the first rule closes the run.
        let mut open = false;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            match key.as_str() {
                "user-agent" => {
                    if !open {
                        groups.push(Group::default());
                        open = true;
                    }
                    if let Some(g) = groups.last_mut() {
                        g.agents.push(value.to_ascii_lowercase());
                    }
                }
                "allow" | "disallow" => {
                    open = false;
                    let Some(g) = groups.last_mut() else {
                        continue;
                    };
                    // An empty Disallow allows everything: no rule.
                    if value.is_empty() {
                        continue;
                    }
                    g.rules.push(Rule {
                        allow: key == "allow",
                        pattern: value.to_string(),
                    });
                }
                _ => {}
            }
        }
        Robots { groups }
    }

    /// Whether `agent` may fetch `path` (path plus query, starting with `/`).
    pub fn allowed(&self, agent: &str, path: &str) -> bool {
        let agent = agent.to_ascii_lowercase();
        let own: Vec<&Group> = self
            .groups
            .iter()
            .filter(|g| {
                g.agents
                    .iter()
                    .any(|a| a != "*" && agent.starts_with(a.as_str()))
            })
            .collect();
        let chosen: Vec<&Group> = if own.is_empty() {
            self.groups
                .iter()
                .filter(|g| g.agents.iter().any(|a| a == "*"))
                .collect()
        } else {
            own
        };
        let mut best: Option<(usize, bool)> = None;
        for rule in chosen.iter().flat_map(|g| g.rules.iter()) {
            if !matches(&rule.pattern, path) {
                continue;
            }
            let len = rule.pattern.len();
            best = match best {
                Some((l, a)) if l > len || (l == len && a) => Some((l, a)),
                _ => Some((len, rule.allow)),
            };
        }
        best.is_none_or(|(_, allow)| allow)
    }
}

/// `*` matches any run, a final `$` anchors the end; otherwise a prefix match.
fn matches(pattern: &str, path: &str) -> bool {
    let (pattern, anchored) = match pattern.strip_suffix('$') {
        Some(p) => (p, true),
        None => (pattern, false),
    };
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut at = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if !path.starts_with(part) {
                return false;
            }
            at = part.len();
            continue;
        }
        let last = i == parts.len() - 1;
        if last && anchored {
            return path.len() >= at + part.len() && path.ends_with(part);
        }
        match path[at..].find(part) {
            Some(k) => at += k + part.len(),
            None => return false,
        }
    }
    !anchored || at == path.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_group_disallows_login() {
        let r = Robots::parse("User-agent: *\nDisallow: /login\n");
        assert!(!r.allowed(AGENT, "/login"));
        assert!(!r.allowed(AGENT, "/login?next=/"));
        assert!(r.allowed(AGENT, "/signup"));
    }

    #[test]
    fn own_group_wins_over_star() {
        let r = Robots::parse(
            "User-agent: *\nDisallow: /\n\nUser-agent: onepassbench\nAllow: /login\nDisallow: /admin\n",
        );
        assert!(r.allowed(AGENT, "/login"));
        assert!(r.allowed(AGENT, "/other"));
        assert!(!r.allowed(AGENT, "/admin"));
        assert!(!r.allowed("SomeoneElse", "/login"));
    }

    #[test]
    fn longest_match_wins_and_allow_wins_ties() {
        let r = Robots::parse("User-agent: *\nDisallow: /account\nAllow: /account/login\n");
        assert!(r.allowed(AGENT, "/account/login"));
        assert!(!r.allowed(AGENT, "/account/settings"));
        let tie = Robots::parse("User-agent: *\nDisallow: /a\nAllow: /a\n");
        assert!(tie.allowed(AGENT, "/a"));
    }

    #[test]
    fn wildcards() {
        let r = Robots::parse("User-agent: *\nDisallow: /*.php$\nDisallow: /*/signin\n");
        assert!(!r.allowed(AGENT, "/index.php"));
        assert!(r.allowed(AGENT, "/index.php?x=1"));
        assert!(!r.allowed(AGENT, "/en/signin"));
        assert!(r.allowed(AGENT, "/signin"));
    }

    #[test]
    fn empty_and_noise_allow_everything() {
        assert!(Robots::parse("").allowed(AGENT, "/login"));
        assert!(Robots::parse("<html>not found</html>").allowed(AGENT, "/login"));
        assert!(Robots::parse("User-agent: *\nDisallow:\n").allowed(AGENT, "/login"));
    }

    #[test]
    fn grouped_agents_and_comments() {
        let r = Robots::parse(
            "# hi\nUser-agent: Googlebot\nUser-agent: OnePassBench # us\nDisallow: /x\nUser-agent: *\nDisallow: /\n",
        );
        assert!(!r.allowed(AGENT, "/x"));
        assert!(r.allowed(AGENT, "/y"));
    }
}
