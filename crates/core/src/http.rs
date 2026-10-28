//! The one HTTP client: OAuth usage, token refresh and profile requests.
//!
//! Tokens travel only as a sensitive `Authorization` header or inside the
//! request body; nothing is logged, and response bodies are moved straight
//! into a [`Secret`] (a refresh response carries tokens). The client is
//! HTTPS-only, follows no redirects, times out after 5 s and sends
//! `User-Agent: claude-multi-auth/<version>`. TLS is rustls with the `ring`
//! provider; certificates are checked by the platform verifier.
//!
//! Everything above this module talks to the [`HttpClient`] trait, so tests
//! use fakes and never reach the network.

use std::sync::OnceLock;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{Error, Result, ToolFailure};
use crate::identity::{Profile, ProfileClient, parse_profile};
use crate::secret::Secret;

/// `anthropic-beta` value the OAuth API endpoints require.
pub const OAUTH_BETA: &str = "oauth-2025-04-20";
pub const PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";
pub const TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound on a response body; the endpoints return a few KiB.
pub const MAX_BODY: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// One request. `what` names the endpoint in errors (never the URL query or
/// any header value).
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub what: &'static str,
    pub method: Method,
    pub url: &'a str,
    /// Sent as `Authorization: Bearer <token>`, marked sensitive.
    pub bearer: Option<&'a Secret>,
    /// Send `anthropic-beta: oauth-2025-04-20`.
    pub oauth_beta: bool,
    /// JSON request body (`Content-Type: application/json`).
    pub json: Option<&'a Secret>,
}

/// A response: status and the raw body.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Secret,
}

/// Sends requests. Implementations must not log requests or responses and
/// must time out. `Send + Sync`: accounts are processed in parallel.
pub trait HttpClient: Send + Sync {
    fn send(&self, req: &Request<'_>) -> Result<Response>;
}

/// Transport failure (no HTTP status): connection, TLS, timeout, body.
pub fn transport_error(what: &'static str) -> Error {
    Error::ExternalTool {
        program: "http",
        sub: what,
        code: None,
        class: ToolFailure::Other,
    }
}

/// A non-success HTTP status. The body is never included.
pub fn status_error(what: &'static str, status: u16) -> Error {
    Error::ExternalTool {
        program: "http",
        sub: what,
        code: Some(i32::from(status)),
        class: if status == 401 || status == 403 {
            ToolFailure::AuthFailed
        } else {
            ToolFailure::Other
        },
    }
}

/// The real client (reqwest, blocking API on its own runtime thread).
///
/// Must not be created, used or dropped on a thread that is driving an
/// async runtime: reqwest's blocking client panics there.
pub struct ReqwestClient {
    client: reqwest::blocking::Client,
}

fn install_ring_provider() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        // Err means a provider is already installed process-wide; keep it.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl ReqwestClient {
    pub fn new() -> Result<Self> {
        install_ring_provider();
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .connect_timeout(TIMEOUT)
            .user_agent(format!("claude-multi-auth/{}", crate::VERSION))
            .build()
            .map_err(|_| transport_error("client"))?;
        Ok(ReqwestClient { client })
    }
}

impl HttpClient for ReqwestClient {
    fn send(&self, req: &Request<'_>) -> Result<Response> {
        use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
        use std::io::Read;
        let mut rb = match req.method {
            Method::Get => self.client.get(req.url),
            Method::Post => self.client.post(req.url),
        };
        if let Some(tok) = req.bearer {
            let mut v = Zeroizing::new(Vec::with_capacity(7 + tok.len()));
            v.extend_from_slice(b"Bearer ");
            v.extend_from_slice(tok.expose());
            let mut hv = HeaderValue::from_bytes(&v).map_err(|_| Error::Invalid {
                what: "access token (unexpected characters)",
                value: String::new(),
            })?;
            hv.set_sensitive(true);
            rb = rb.header(AUTHORIZATION, hv);
        }
        if req.oauth_beta {
            rb = rb.header("anthropic-beta", OAUTH_BETA);
        }
        if let Some(body) = req.json {
            rb = rb
                .header(CONTENT_TYPE, "application/json")
                .body(body.expose().to_vec());
        }
        let resp = rb.send().map_err(|_| transport_error(req.what))?;
        let status = resp.status().as_u16();
        if resp.content_length().is_some_and(|n| n > MAX_BODY as u64) {
            return Err(transport_error(req.what));
        }
        // Read at most one byte past the limit, so an endless body without
        // a length is cut off instead of buffered.
        let mut body = Zeroizing::new(Vec::new());
        std::io::Read::take(resp, MAX_BODY as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| transport_error(req.what))?;
        if body.len() > MAX_BODY {
            return Err(transport_error(req.what));
        }
        Ok(Response {
            status,
            body: Secret::new(std::mem::take(&mut *body)),
        })
    }
}

/// `GET /api/oauth/profile` through an [`HttpClient`].
pub fn fetch_profile(http: &dyn HttpClient, access_token: &Secret) -> Result<Profile> {
    const WHAT: &str = "oauth/profile";
    let resp = http.send(&Request {
        what: WHAT,
        method: Method::Get,
        url: PROFILE_URL,
        bearer: Some(access_token),
        oauth_beta: true,
        json: None,
    })?;
    if resp.status != 200 {
        return Err(status_error(WHAT, resp.status));
    }
    parse_profile(resp.body.expose())
}

/// [`ProfileClient`] over an [`HttpClient`].
pub struct HttpProfileClient<'a>(pub &'a dyn HttpClient);

impl ProfileClient for HttpProfileClient<'_> {
    fn profile(&self, access_token: &Secret) -> Result<Profile> {
        fetch_profile(self.0, access_token)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// What a fake saw. The bearer and body are kept so tests can assert
    /// on them (dummy tokens only).
    #[derive(Debug, Clone)]
    pub struct Seen {
        pub what: &'static str,
        pub method: Method,
        pub url: String,
        pub bearer: Option<String>,
        pub oauth_beta: bool,
        pub json: Option<serde_json::Value>,
    }

    type Handler = Box<dyn Fn(&Seen) -> Result<Response> + Send + Sync>;

    /// Fake client: records every request and answers with a handler.
    pub struct FakeHttp {
        pub seen: Mutex<Vec<Seen>>,
        handler: Handler,
        scripted: Mutex<VecDeque<Result<Response>>>,
    }

    pub fn resp(status: u16, body: &str) -> Result<Response> {
        Ok(Response {
            status,
            body: Secret::new(body.as_bytes().to_vec()),
        })
    }

    impl FakeHttp {
        pub fn new(handler: impl Fn(&Seen) -> Result<Response> + Send + Sync + 'static) -> Self {
            FakeHttp {
                seen: Mutex::new(Vec::new()),
                handler: Box::new(handler),
                scripted: Mutex::new(VecDeque::new()),
            }
        }

        /// Answer the next requests with these, before the handler.
        pub fn script(&self, r: Result<Response>) {
            self.scripted.lock().unwrap().push_back(r);
        }

        pub fn count(&self, what: &str) -> usize {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.what == what)
                .count()
        }

        pub fn requests(&self, what: &str) -> Vec<Seen> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.what == what)
                .cloned()
                .collect()
        }
    }

    impl HttpClient for FakeHttp {
        fn send(&self, req: &Request<'_>) -> Result<Response> {
            let seen = Seen {
                what: req.what,
                method: req.method,
                url: req.url.to_string(),
                bearer: req
                    .bearer
                    .map(|b| String::from_utf8(b.expose().to_vec()).unwrap()),
                oauth_beta: req.oauth_beta,
                json: req
                    .json
                    .map(|j| serde_json::from_slice(j.expose()).unwrap()),
            };
            self.seen.lock().unwrap().push(seen.clone());
            if let Some(r) = self.scripted.lock().unwrap().pop_front() {
                return r;
            }
            (self.handler)(&seen)
        }
    }

    #[test]
    fn profile_over_http_sends_bearer_and_beta() {
        let f = FakeHttp::new(|_| {
            resp(
                200,
                r#"{"account":{"uuid":"a-1","email":"e@x"},"organization":{"uuid":"o-1","name":"O"}}"#,
            )
        });
        let p = HttpProfileClient(&f)
            .profile(&Secret::new(b"at-dummy".to_vec()))
            .unwrap();
        assert_eq!(p.key(), "a-1::o-1");
        let s = &f.requests("oauth/profile")[0];
        assert_eq!(s.url, PROFILE_URL);
        assert_eq!(s.method, Method::Get);
        assert_eq!(s.bearer.as_deref(), Some("at-dummy"));
        assert!(s.oauth_beta);
        assert!(s.json.is_none());
    }

    #[test]
    fn profile_status_error_carries_no_body() {
        let f = FakeHttp::new(|_| resp(401, r#"{"error":"at-dummy leaked?"}"#));
        let e = fetch_profile(&f, &Secret::new(b"at-dummy".to_vec())).unwrap_err();
        assert!(matches!(
            e,
            Error::ExternalTool {
                program: "http",
                code: Some(401),
                class: ToolFailure::AuthFailed,
                ..
            }
        ));
        assert!(!e.to_string().contains("dummy"));
    }

    #[test]
    fn real_client_builds_and_refuses_plain_http_without_network() {
        let c = ReqwestClient::new().unwrap();
        // https_only: refused before any connection is attempted.
        let e = c
            .send(&Request {
                what: "oauth/usage",
                method: Method::Get,
                url: "http://127.0.0.1:9/api/oauth/usage",
                bearer: Some(&Secret::new(b"dummy".to_vec())),
                oauth_beta: true,
                json: None,
            })
            .unwrap_err();
        assert!(matches!(e, Error::ExternalTool { code: None, .. }));
        assert!(!format!("{e:?}").contains("dummy"));
    }

    #[test]
    fn bearer_with_control_characters_is_refused() {
        let c = ReqwestClient::new().unwrap();
        let e = c
            .send(&Request {
                what: "oauth/usage",
                method: Method::Get,
                url: "https://127.0.0.1:9/",
                bearer: Some(&Secret::new(b"a\nb".to_vec())),
                oauth_beta: false,
                json: None,
            })
            .unwrap_err();
        assert!(matches!(e, Error::Invalid { .. }));
    }
}
