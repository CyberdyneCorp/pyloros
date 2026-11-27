//! Register an active organization in the operator directory.
use super::*;
use crate::profile::admin_fields::trimmed;
use crate::{grant_response::SessionOrigin, login_http::problem, request_json::fields};

pub(super) struct NewOrganization {
    pub(super) name: String,
    pub(super) short_name: Option<String>,
    pub(super) domain: Option<String>,
    pub(super) github: Option<String>,
    pub(super) description: Option<String>,
    pub(super) metadata: Value,
}

pub(in crate::profile) async fn create(
    State(state): State<Arc<Profile>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let body = match fields::document(&headers, &bytes) {
        Ok(body) => body,
        Err(error) => return *error,
    };
    let (tx, actor, email) = match administrator::operator(&state, &headers).await {
        Ok(operator) => operator,
        Err(error) => return *error,
    };
    let Some(body) = body else { return internal() };
    let organization = match input::parse(&body) {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let origin = SessionOrigin {
        ip: crate::token_http::client_ip(&headers, peer.ip(), state.proxies),
        user_agent: crate::token_http::header(&headers, "user-agent"),
    };
    organization
        .insert(tx, (actor, email.as_deref()), origin)
        .await
        .unwrap_or_else(|_| internal())
}

impl NewOrganization {
    async fn insert(
        self,
        mut tx: Transaction<'_, Postgres>,
        actor: (Uuid, Option<&str>),
        origin: SessionOrigin<'_>,
    ) -> Result<Response, sqlx::Error> {
        if let Some(domain) = self.domain.as_deref().filter(|v| !v.is_empty())
            && taken(&mut tx, "lower(domain_name)=$1", domain, None).await?
        {
            return Ok(problem(
                StatusCode::CONFLICT,
                &format!("Domain already in use: {domain}"),
            ));
        }
        let github = normalized(self.github.as_deref());
        if let Some(login) = github.filter(|v| !v.is_empty())
            && taken(&mut tx, "is_active AND lower(github_login)=$1", login, None).await?
        {
            return Ok(problem(
                StatusCode::CONFLICT,
                &format!("GitHub login already in use: {login}"),
            ));
        }
        let name = trimmed(&self.name);
        let domain = normalized(self.domain.as_deref()).map(str::to_lowercase);
        let id = Uuid::new_v4();
        let sql = format!(
            "INSERT INTO organizations AS o
            (id,name,short_name,domain_name,github_login,description,extra_metadata,is_active)
            VALUES($1,$2,$3,$4,$5,$6,$7,true) RETURNING {COLUMNS}"
        );
        let row = sqlx::query_as::<_, DirectoryRow>(&sql)
            .bind(id)
            .bind(name)
            .bind(normalized(self.short_name.as_deref()))
            .bind(&domain)
            .bind(github)
            .bind(normalized(self.description.as_deref()))
            .bind(&self.metadata)
            .fetch_one(&mut *tx)
            .await?;
        let record = item(row)?;
        crate::admin_audit::append(
            &mut tx,
            "organization.create",
            Some(actor),
            ("organization", &id.to_string()),
            json!({"name":name,"domain_name":domain}),
            origin,
        )
        .await?;
        tx.commit().await?;
        Ok((StatusCode::CREATED, Json(record)).into_response())
    }
}

pub(super) async fn taken(
    tx: &mut Transaction<'_, Postgres>,
    predicate: &'static str,
    value: &str,
    exclude: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let rows = sqlx::query_as::<_, (Uuid, String)>(&format!(
        "SELECT id,extra_metadata::text FROM organizations WHERE {predicate} LIMIT 2"
    ))
    .bind(value.to_lowercase())
    .fetch_all(&mut **tx)
    .await?;
    if rows.len() > 1 {
        return Err(sqlx::Error::Protocol(
            "ambiguous organization mapping".into(),
        ));
    }
    if let Some((id, metadata)) = rows.first() {
        metadata::strings(metadata).map_err(|e| sqlx::Error::Decode(e.into()))?;
        return Ok(Some(*id) != exclude);
    }
    Ok(false)
}

pub(super) fn normalized(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty()).map(trimmed)
}
