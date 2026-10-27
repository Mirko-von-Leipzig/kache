//! Anonymous S3 reads through a bucket-root CDN endpoint.
//!
//! OpenDAL retains its S3 response parsing, streaming limits, and pagination.
//! Only the read transport changes: no bucket segment or AWS credentials reach
//! the CDN, and redirects cannot move downloads back to a billable S3 endpoint.

use anyhow::{Context, Result, ensure};
use http::{Method, Request, Response};
use opendal::{
    Buffer, Error, ErrorKind, HttpBody, HttpTransport, HttpTransporter, OperationContext, Operator,
};
use opendal_http_transport_reqwest::ReqwestTransport;
use opendal_service_s3::S3;

use super::{
    CONNECT_TIMEOUT, READ_INACTIVITY_TIMEOUT, ensure_rustls_provider, without_retry_layer,
};

struct DownloadTransport {
    base: String,
    transport: ReqwestTransport,
}

impl HttpTransport for DownloadTransport {
    async fn fetch(&self, mut request: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "the download endpoint is read-only",
            ));
        }
        let path = request
            .uri()
            .path()
            .strip_prefix("/download")
            .filter(|path| path.is_empty() || path.starts_with('/'))
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "unexpected S3 download path"))?;
        let path = if path.is_empty() { "/" } else { path };
        let mut url = format!("{}{path}", self.base);
        if let Some(query) = request.uri().query() {
            url.push('?');
            url.push_str(query);
        }
        *request.uri_mut() = url.parse().map_err(|error| {
            Error::new(ErrorKind::ConfigInvalid, "invalid download URL").set_source(error)
        })?;
        // Removes identity headers from anonymous downloads.
        //
        // Signing is disabled; this also protects against later transport changes.
        for name in ["authorization", "x-amz-security-token", "host"] {
            request.headers_mut().remove(name);
        }
        self.transport.fetch(request).await
    }
}

pub(super) fn operator(
    endpoint: &str,
    pool_idle_secs: u64,
    user_agent: Option<&str>,
) -> Result<Operator> {
    let url = reqwest::Url::parse(endpoint).context("invalid S3 download_endpoint")?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "download_endpoint requires HTTPS (HTTP is allowed only for loopback tests)"
    );
    ensure!(
        url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "download_endpoint must be a base URL without credentials, query, or fragment"
    );
    ensure_rustls_provider();
    let mut client = reqwest::Client::builder()
        .pool_idle_timeout(std::time::Duration::from_secs(pool_idle_secs))
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_INACTIVITY_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(agent) = user_agent.filter(|agent| !agent.trim().is_empty()) {
        client = client.user_agent(agent);
    }
    let transport = DownloadTransport {
        base: url.as_str().trim_end_matches('/').to_string(),
        transport: ReqwestTransport::new(client.build()?),
    };
    // Supplies S3 request paths from a synthetic endpoint.
    //
    // The transport replaces the URL before sending; the endpoint never receives
    // a network request or triggers a credential lookup.
    let builder = S3::default()
        .bucket("download")
        .region("us-east-1")
        .endpoint("https://kache-download.invalid")
        .skip_signature();
    let context = OperationContext::new().with_http_transport(HttpTransporter::new(transport));
    Ok(without_retry_layer(
        Operator::new(builder)?.with_context(context),
    ))
}
