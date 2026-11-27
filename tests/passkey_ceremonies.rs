use pyloros::passkey_ceremonies::Enrollment;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

async fn begin<'a>(pool: &'a PgPool, schema: &str) -> Transaction<'a, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('search_path', $1, true)")
        .bind(schema)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn enrollment_claim_is_bound_expiring_and_committed_once() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let schema = format!("enrollment_{}", Uuid::new_v4().simple());
    let mut setup = pool.begin().await.unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut *setup)
        .await
        .unwrap();
    sqlx::query(&format!(
        "CREATE TABLE {schema}.passkey_ceremonies (
        id uuid PRIMARY KEY, purpose text, user_id uuid, session_id uuid, rp_id text,
        origin text, binding_hash text, policy text, challenge bytea,
        consumed_at timestamptz, expires_at timestamptz)"
    ))
    .execute(&mut *setup)
    .await
    .unwrap();
    setup.commit().await.unwrap();

    let enrollment = Enrollment {
        user: Uuid::new_v4(),
        session: Uuid::new_v4(),
        relying_party: "example.test",
        origin: "https://example.test",
        binding: "client secret",
        policy_digest: "first policy",
    };
    let challenge = [42; 32];
    let mut tx = begin(&pool, &schema).await;
    let id = enrollment.issue(&mut tx, &challenge, 300).await.unwrap();
    let expired = enrollment.issue(&mut tx, &challenge, -1).await.unwrap();
    let other = enrollment.issue(&mut tx, &challenge, 300).await.unwrap();
    sqlx::query("UPDATE passkey_ceremonies SET purpose='reauth' WHERE id=$1")
        .bind(other)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    for invalid in [
        Enrollment {
            user: Uuid::new_v4(),
            ..enrollment
        },
        Enrollment {
            session: Uuid::new_v4(),
            ..enrollment
        },
        Enrollment {
            relying_party: "other.test",
            ..enrollment
        },
        Enrollment {
            origin: "https://other.example.test",
            ..enrollment
        },
        Enrollment {
            binding: "another browser",
            ..enrollment
        },
        Enrollment {
            policy_digest: "changed",
            ..enrollment
        },
    ] {
        assert!(
            invalid
                .claim(begin(&pool, &schema).await, id)
                .await
                .unwrap()
                .is_none()
        );
    }
    for invalid_id in [expired, other, Uuid::new_v4()] {
        assert!(
            enrollment
                .claim(begin(&pool, &schema).await, invalid_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    let binding = pyloros::passkey_ceremonies::CeremonyBinding {
        relying_party: enrollment.relying_party,
        origin: enrollment.origin,
        binding: enrollment.binding,
        policy_digest: enrollment.policy_digest,
    };
    let mut tx = begin(&pool, &schema).await;
    let login_id = binding.issue_login(&mut tx, &challenge, 60).await.unwrap();
    tx.commit().await.unwrap();
    assert!(
        enrollment
            .claim(begin(&pool, &schema).await, login_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        binding
            .claim_login(begin(&pool, &schema).await, id)
            .await
            .unwrap()
            .is_none()
    );
    let first = begin(&pool, &schema).await;
    let second = begin(&pool, &schema).await;
    let (first, second) = tokio::join!(
        binding.claim_login(first, login_id),
        binding.claim_login(second, login_id)
    );
    let claimed: Vec<_> = [first.unwrap(), second.unwrap()]
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(claimed, [challenge.to_vec()]);

    let a = begin(&pool, &schema).await;
    let b = begin(&pool, &schema).await;
    let (a, b) = tokio::join!(enrollment.claim(a, id), enrollment.claim(b, id));
    let winners: Vec<_> = [a.unwrap(), b.unwrap()].into_iter().flatten().collect();
    assert_eq!(winners, [challenge.to_vec()]);
    let mut later = begin(&pool, &schema).await;
    sqlx::query("UPDATE passkey_ceremonies SET consumed_at=NULL WHERE id=$1")
        .bind(id)
        .execute(&mut *later)
        .await
        .unwrap();
    later.rollback().await.unwrap();
    assert!(
        enrollment
            .claim(begin(&pool, &schema).await, id)
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .unwrap();
}
