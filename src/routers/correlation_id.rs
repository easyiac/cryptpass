use axum::body::Body;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing::trace;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct CorrelationId {
    #[allow(dead_code)]
    pub(crate) correlation_id: String,
}

pub(crate) async fn set_correlation_id(mut request: Request<Body>, next: Next) -> Response {
    let correlation_id = Uuid::new_v4().to_string();
    trace!("Setting correlation_id: {}", correlation_id);
    request.extensions_mut().insert(CorrelationId { correlation_id });
    next.run(request).await
}
