//! Download audit rows in time order, with backpressure from the response body.
use super::*;
use axum::body::Body;
use futures_util::stream;
use std::{borrow::Cow, collections::HashMap, convert::Infallible};

pub(super) async fn read(
    State(state): State<Arc<Profile>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    if method != Method::GET {
        return crate::browser_http::method_not_allowed().await;
    }
    let (tx, _, _) = match administrator::operator(&state, &headers).await {
        Ok(actor) => actor,
        Err(e) => return *e,
    };
    let bounds = match Bounds::parse(raw.as_deref().unwrap_or_default()) {
        Ok(bounds) => bounds,
        Err(e) => return passkeys::validation(e),
    };
    let export = Export {
        tx,
        bounds,
        offset: 0,
        pending: Vec::new().into_iter(),
        finished: false,
    };
    let body = stream::unfold(export, |mut export| async move {
        match export.next_line().await {
            Ok(Some(line)) => Some((Ok::<_, Infallible>(line), export)),
            Ok(None) => None,
            Err(_) => {
                eprintln!("audit export stopped while reading retained history");
                None
            }
        }
    });
    (
        [
            (header::CONTENT_TYPE, "application/x-ndjson"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=audit-log.ndjson",
            ),
        ],
        Body::from_stream(body),
    )
        .into_response()
}

struct Bounds {
    from: Option<datetime::ParsedDateTime>,
    to: Option<datetime::ParsedDateTime>,
}

impl Bounds {
    fn parse(raw: &str) -> Result<Self, Vec<Value>> {
        let values: HashMap<Cow<'_, str>, Cow<'_, str>> =
            url::form_urlencoded::parse(raw.as_bytes()).collect();
        let mut issues = Vec::new();
        let mut bound = |key| {
            values.get(key).and_then(|v| {
                let input = json!(v);
                datetime::parse(&input)
                    .map_err(|mut e| {
                        e["loc"] = json!(["query", key]);
                        e["input"] = input;
                        issues.push(e)
                    })
                    .ok()
            })
        };
        let bounds = Self {
            from: bound("from"),
            to: bound("to"),
        };
        if issues.is_empty() {
            Ok(bounds)
        } else {
            Err(issues)
        }
    }
}

struct Export {
    tx: Transaction<'static, Postgres>,
    bounds: Bounds,
    offset: i64,
    pending: std::vec::IntoIter<PgRow>,
    finished: bool,
}

impl Export {
    async fn next_line(&mut self) -> sqlx::Result<Option<String>> {
        const BATCH: i64 = 1000;
        if self.pending.len() == 0 && !self.finished {
            let rows = sqlx::query(
                "SELECT id,action,actor_email,actor_type,actor_user_id,
                actor_client_id,target_id,target_type,timestamptz_send(created_at) AS event_time,extra_metadata::text AS metadata,
                host(ip_address) AS ip,masklen(ip_address) AS prefix,user_agent,prev_hash,row_hash
                FROM admin_action_logs WHERE ($1::text IS NULL OR created_at >= $1::text::timestamptz)
                AND ($2::text IS NULL OR created_at <= $2::text::timestamptz)
                ORDER BY created_at,id LIMIT $3 OFFSET $4",
            )
            .bind(self.bounds.from.as_ref().map(|d|d.database_bound()).transpose()?)
            .bind(self.bounds.to.as_ref().map(|d|d.database_bound()).transpose()?)
            .bind(BATCH)
            .bind(self.offset)
            .fetch_all(&mut *self.tx)
            .await?;
            // The database driver decodes the complete page before yielding its first row.
            for row in &rows {
                EventTime::read(row)?;
                crate::stored_json::check_integers(row.try_get("metadata")?)?;
            }
            self.finished = rows.len() < BATCH as usize;
            self.offset += rows.len() as i64;
            self.pending = rows.into_iter();
        }
        self.pending.next().map(|row| line(&row)).transpose()
    }
}

// Field order is part of the exported file format.
#[derive(Serialize)]
struct ExportRow<'a> {
    id: Uuid,
    created_at: String,
    action: &'a str,
    actor_user_id: Option<Uuid>,
    actor_email: Option<&'a str>,
    actor_type: &'a str,
    actor_client_id: Option<&'a str>,
    target_type: Option<&'a str>,
    target_id: Option<&'a str>,
    metadata: &'a RawValue,
    ip_address: Option<String>,
    user_agent: Option<&'a str>,
    prev_hash: &'a str,
    row_hash: &'a str,
}

fn line(row: &PgRow) -> sqlx::Result<String> {
    let raw: &str = row.try_get("metadata")?;
    let object = admin_organizations::audit_object(raw, false)?;
    let metadata = serde_json::from_str(object.as_deref().unwrap_or(raw))
        .map_err(|e| sqlx::Error::Decode(e.into()))?;
    let event = ExportRow {
        id: row.try_get("id")?,
        created_at: EventTime::read(row)?.display("+00:00"),
        action: row.try_get("action")?,
        actor_user_id: row.try_get("actor_user_id")?,
        actor_email: row.try_get("actor_email")?,
        actor_type: row
            .try_get::<Option<&str>, _>("actor_type")?
            .filter(|s| !s.is_empty())
            .unwrap_or("user"),
        actor_client_id: row.try_get("actor_client_id")?,
        target_type: row.try_get("target_type")?,
        target_id: row.try_get("target_id")?,
        metadata,
        ip_address: address(row.try_get("ip")?, row.try_get("prefix")?)?,
        user_agent: row.try_get("user_agent")?,
        prev_hash: row.try_get("prev_hash")?,
        row_hash: row.try_get("row_hash")?,
    };
    serde_json::to_string(&event)
        .and_then(|json| download_line(&json))
        .map_err(|e| sqlx::Error::Encode(e.into()))
}

fn download_line(mut json: &str) -> serde_json::Result<String> {
    let mut out = String::with_capacity(json.len());
    while !json.is_empty() {
        let byte = json.as_bytes()[0];
        match byte {
            b'"' => {
                let mut values = serde_json::Deserializer::from_str(json).into_iter::<String>();
                let text = values.next().expect("JSON string")?;
                out.push_str(&crate::admin_audit::ascii(&serde_json::to_string(&text)?));
                json = &json[values.byte_offset()..];
                continue;
            }
            b'0'..=b'9' | b'-' => {
                let end = json
                    .find([',', ']', '}', ' ', '\t', '\n', '\r'])
                    .unwrap_or(json.len());
                let number = &json[..end];
                if number.contains(['e', 'E', '.']) {
                    let f = number.parse::<f64>().expect("JSON number");
                    out.push_str(&match f {
                        f64::INFINITY => "Infinity".into(),
                        f64::NEG_INFINITY => "-Infinity".into(),
                        _ => crate::json_representation::float_literal(f),
                    });
                } else {
                    out.push_str(number)
                }
                json = &json[end..];
                continue;
            }
            b',' => out.push_str(", "),
            b':' => out.push_str(": "),
            c if c.is_ascii_whitespace() => (),
            c => out.push(c as char),
        }
        json = &json[1..];
    }
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_encoding_preserves_integer_digits_and_escapes_string_delimiters() {
        let raw = r#"{"n":[123456789012345678901,0.00001],"x":"Ω:,\n"}"#;
        assert_eq!(
            download_line(raw).unwrap(),
            concat!(
                r#"{"n": [123456789012345678901, 1e-05], "x": "\u03a9:,\n"}"#,
                "\n"
            )
        );
    }
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn a_late_invalid_row_leaves_all_preceding_records_available() -> sqlx::Result<()> {
        let pool = PgPool::connect(&env::var("DATABASE_URL").unwrap()).await?;
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(
            "CREATE TEMP TABLE admin_action_logs (
            id uuid,action text,actor_email text,actor_type text,actor_user_id uuid,
            actor_client_id text,target_id text,target_type text,created_at timestamptz,
            extra_metadata jsonb,ip_address inet,user_agent text,prev_hash text,row_hash text);
            INSERT INTO admin_action_logs(id,action,created_at,extra_metadata,prev_hash,row_hash)
            SELECT gen_random_uuid(),'test',now()+n*interval '1 second',
              CASE WHEN n=1002 THEN 'true'::jsonb ELSE '{}'::jsonb END,'prior',n::text
            FROM generate_series(1,1002) n",
        )
        .execute(&mut *tx)
        .await?;
        let mut export = Export {
            tx,
            bounds: Bounds {
                from: None,
                to: None,
            },
            offset: 0,
            pending: Vec::new().into_iter(),
            finished: false,
        };
        for expected in 1..=1001 {
            let line = export.next_line().await?.expect("complete event");
            let row: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(row["row_hash"], expected.to_string());
        }
        assert!(export.next_line().await.is_err());
        Ok(())
    }
}
