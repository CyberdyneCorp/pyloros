use chrono::{TimeDelta, Utc};
use pyloros::token_revocation::{Outcome, VerifiedToken, revoke};
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

async fn isolated_tables() -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE TEMP TABLE revoked_tokens(jti uuid PRIMARY KEY,expires_at timestamptz,client_id text,reason text,revoked_at timestamptz);
         CREATE TEMP TABLE sessions(id uuid PRIMARY KEY,revoked_at timestamptz);
         CREATE TEMP TABLE refresh_tokens(jti uuid PRIMARY KEY,session_id uuid,client_id text,revoked_at timestamptz);"
    ).execute(&pool).await.unwrap();
    pool
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn refresh_ownership_controls_family_revocation_and_rollback() {
    let pool = isolated_tables().await;
    let session = Uuid::new_v4();
    let id = Uuid::new_v4();
    let unrelated = Uuid::new_v4();
    let user = Uuid::new_v4();
    let now = Utc::now();
    sqlx::query("INSERT INTO sessions VALUES ($1,NULL),($2,NULL)")
        .bind(session)
        .bind(unrelated)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO refresh_tokens VALUES ($1,$2,'app',NULL),($3,$2,'app',NULL),($4,$5,NULL,NULL)",
    )
    .bind(id)
    .bind(session)
    .bind(Uuid::new_v4())
    .bind(unrelated)
    .bind(unrelated)
    .execute(&pool)
    .await
    .unwrap();
    let token = VerifiedToken::Refresh { id, session, user };
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(
        revoke(&mut tx, "other", &token, now).await.unwrap(),
        Outcome::DifferentOwner
    );
    let first_party = VerifiedToken::Refresh {
        id: unrelated,
        session: unrelated,
        user,
    };
    assert_eq!(
        revoke(&mut tx, "app", &first_party, now).await.unwrap(),
        Outcome::DifferentOwner
    );
    let absent = VerifiedToken::Refresh {
        id: Uuid::new_v4(),
        session,
        user,
    };
    assert_eq!(
        revoke(&mut tx, "app", &absent, now).await.unwrap(),
        Outcome::Unknown
    );
    tx.commit().await.unwrap();
    for commit in [false, true] {
        let mut tx = pool.begin().await.unwrap();
        let live = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(live, 3);
        assert_eq!(
            revoke(&mut tx, "app", &token, now).await.unwrap(),
            Outcome::Revoked
        );
        if commit {
            tx.commit().await.unwrap()
        } else {
            tx.rollback().await.unwrap()
        }
    }
    let active_sessions =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM sessions WHERE revoked_at IS NULL")
            .fetch_all(&pool)
            .await
            .unwrap();
    let live =
        sqlx::query_scalar::<_, Uuid>("SELECT jti FROM refresh_tokens WHERE revoked_at IS NULL")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(active_sessions, [unrelated]);
    assert_eq!(live, [unrelated]);
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn access_and_service_revocations_preserve_first_record_and_other_owners() {
    let pool = isolated_tables().await;
    let now = Utc::now();
    let expires = now + TimeDelta::minutes(15);
    let user = Uuid::new_v4();
    let access = Uuid::new_v4();
    let service = Uuid::new_v4();
    let mut tx = pool.begin().await.unwrap();
    for token in [
        VerifiedToken::Access {
            id: access,
            expires,
            client: Some("app".into()),
            user,
        },
        VerifiedToken::Service {
            id: service,
            expires,
            client: "app".into(),
        },
    ] {
        assert_eq!(
            revoke(&mut tx, "other", &token, now).await.unwrap(),
            Outcome::DifferentOwner
        );
        for time in [now, now + TimeDelta::seconds(1)] {
            assert_eq!(
                revoke(&mut tx, "app", &token, time).await.unwrap(),
                Outcome::Revoked
            );
        }
    }
    let first_party = VerifiedToken::Access {
        id: Uuid::new_v4(),
        expires,
        client: None,
        user,
    };
    assert_eq!(
        revoke(&mut tx, "app", &first_party, now).await.unwrap(),
        Outcome::DifferentOwner
    );
    tx.commit().await.unwrap();
    let rows=sqlx::query_scalar::<_,bool>("SELECT client_id='app' AND reason='revocation' AND revoked_at=$1 AND expires_at=$2 AND jti IN ($3,$4) FROM revoked_tokens").bind(now).bind(expires).bind(access).bind(service).fetch_all(&pool).await.unwrap();
    assert_eq!(rows, [true, true]);
}
