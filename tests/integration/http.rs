use crate::util::{Server, http_request};

#[test]
fn get_root_serves_welcome_page() {
    let server = Server::start("get_root_serves_welcome_page");
    let resp = server.get("/");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("Content-Type"), Some("text/html"));
    assert_eq!(resp.header("Connection"), Some("close"));
    assert_eq!(
        resp.header("Content-Length"),
        Some(resp.body.len().to_string().as_str())
    );
    assert!(
        resp.body.contains("<h1>Hello from Monoio!</h1>"),
        "{}",
        resp.body
    );
}

#[test]
fn get_health_is_ok_json() {
    let server = Server::start("get_health_is_ok_json");
    let resp = server.get("/health");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("Content-Type"), Some("application/json"));
    assert_eq!(resp.body, r#"{"status":"ok"}"#);
}

#[test]
fn unknown_path_is_404() {
    let server = Server::start("unknown_path_is_404");
    for path in ["/nope", "/health/", "/index.html"] {
        let resp = server.get(path);
        assert_eq!(resp.status, 404, "GET {path}");
        assert_eq!(
            resp.header("Content-Type"),
            Some("text/plain"),
            "GET {path}"
        );
        assert_eq!(resp.body, "404 Not Found", "GET {path}");
    }
}

#[test]
fn non_get_method_is_404() {
    let server = Server::start("non_get_method_is_404");
    let resp = http_request(
        server.http_addr(),
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )
    .unwrap();
    assert_eq!(resp.status, 404);
}

#[test]
fn serves_many_sequential_connections() {
    let server = Server::start("serves_many_sequential_connections");
    for i in 0..50 {
        assert_eq!(server.get("/health").status, 200, "request {i}");
    }
}
