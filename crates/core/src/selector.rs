//! Resolve a user query to one account.
//!
//! Tried in order, first stage with any match wins: row number (1-based),
//! alias, email, email prefix, key prefix. Matching is case-insensitive.
//! More than one match in a stage is an error listing the candidates.

use crate::error::{Error, Result};
use crate::registry::Account;

pub fn select<'a>(accounts: &'a [Account], query: &str) -> Result<&'a Account> {
    let q = query.trim();
    if q.is_empty() {
        return Err(Error::NotFound("empty account query".into()));
    }
    if q.bytes().all(|b| b.is_ascii_digit())
        && let Ok(n) = q.parse::<usize>()
        && (1..=accounts.len()).contains(&n)
    {
        return Ok(&accounts[n - 1]);
    }
    let ql = q.to_lowercase();
    let stages: [&dyn Fn(&Account) -> bool; 4] = [
        &|a| a.alias.as_deref().is_some_and(|al| al.to_lowercase() == ql),
        &|a| !a.email.is_empty() && a.email.to_lowercase() == ql,
        &|a| !a.email.is_empty() && a.email.to_lowercase().starts_with(&ql),
        &|a| a.key.to_lowercase().starts_with(&ql),
    ];
    for stage in stages {
        let hits: Vec<&Account> = accounts.iter().filter(|a| stage(a)).collect();
        match hits.len() {
            0 => continue,
            1 => return Ok(hits[0]),
            _ => {
                return Err(Error::Ambiguous {
                    query: q.to_string(),
                    candidates: hits.iter().map(|a| describe(a)).collect(),
                });
            }
        }
    }
    Err(Error::NotFound(format!("no account matches {q:?}")))
}

fn describe(a: &Account) -> String {
    let mut s = if a.email.is_empty() {
        a.key.clone()
    } else {
        format!("{} ({})", a.email, a.key)
    };
    if !a.org_name.is_empty() {
        s.push_str(&format!(" [{}]", a.org_name));
    }
    if let Some(al) = &a.alias {
        s.push_str(&format!(" alias={al}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(key: &str, email: &str, alias: Option<&str>) -> Account {
        Account {
            key: key.into(),
            email: email.into(),
            alias: alias.map(Into::into),
            ..Default::default()
        }
    }

    fn fixture() -> Vec<Account> {
        vec![
            acct("aaaa1111::org1", "alice@example.com", Some("work")),
            acct("aaaa1111::org2", "alice@example.com", None),
            acct("bbbb2222::org3", "bob@example.com", Some("Personal")),
        ]
    }

    #[test]
    fn row_alias_email_prefix_key() {
        let a = fixture();
        assert_eq!(select(&a, "3").unwrap().key, "bbbb2222::org3");
        assert_eq!(select(&a, "WORK").unwrap().key, "aaaa1111::org1");
        assert_eq!(select(&a, "personal").unwrap().key, "bbbb2222::org3");
        assert_eq!(select(&a, "bob@example.com").unwrap().key, "bbbb2222::org3");
        assert_eq!(select(&a, "bo").unwrap().key, "bbbb2222::org3");
        assert_eq!(select(&a, "aaaa1111::org2").unwrap().key, "aaaa1111::org2");
    }

    #[test]
    fn ambiguity_lists_candidates() {
        let a = fixture();
        for q in ["alice@example.com", "al", "aaaa"] {
            match select(&a, q) {
                Err(Error::Ambiguous { candidates, .. }) => {
                    assert_eq!(candidates.len(), 2, "{q}");
                    assert!(candidates.iter().all(|c| c.contains("aaaa1111")));
                    let msg = select(&a, q).unwrap_err().to_string();
                    assert!(msg.contains("org1") && msg.contains("org2"), "{msg}");
                }
                other => panic!("{q}: {other:?}"),
            }
        }
    }

    #[test]
    fn not_found_and_out_of_range() {
        let a = fixture();
        assert!(matches!(select(&a, "zzz"), Err(Error::NotFound(_))));
        assert!(matches!(select(&a, "9"), Err(Error::NotFound(_))));
        assert!(matches!(select(&a, "0"), Err(Error::NotFound(_))));
        assert!(matches!(select(&a, " "), Err(Error::NotFound(_))));
    }
}
