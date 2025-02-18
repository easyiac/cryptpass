use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Request},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use std::net::SocketAddr;
use tracing::debug;

pub(crate) async fn print_request_response(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user_agent = request
        .headers()
        .get("user-agent")
        .map(|value| value.to_str().unwrap_or_default())
        .unwrap_or_default()
        .to_string();
    let uri = request.uri().path().to_string();
    let (parts, body) = request.into_parts();
    let req_bytes = buffer_and_print("request", body).await?;
    let req = Request::from_parts(parts, Body::from(req_bytes.clone()));

    let res = next.run(req).await;

    let (parts, body) = res.into_parts();
    let res_bytes = buffer_and_print("response", body).await?;
    let res = Response::from_parts(parts, Body::from(res_bytes.clone()));

    debug!(
        "Request from {addr} {method} {uri} {user_agent} {status} {req_bytes} -> {res_bytes}",
        addr = addr,
        method = method,
        uri = uri,
        status = res.status().as_u16(),
        user_agent = user_agent,
        req_bytes = std::str::from_utf8(&req_bytes).unwrap_or_default(),
        res_bytes = std::str::from_utf8(&res_bytes).unwrap_or_default(),
    );
    Ok(res)
}

async fn buffer_and_print<B>(direction: &str, body: B) -> Result<Bytes, (StatusCode, String)>
where
    B: axum::body::HttpBody<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("failed to read {direction} body: {err}"),
            ));
        }
    };
    Ok(bytes)
}
