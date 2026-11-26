use pyloros::token_authorization::resolve;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL; run just test-db"]
async fn audience_and_membership_constrain_authorization() {
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql("CREATE TEMP TABLE users(id uuid);
        CREATE TEMP TABLE iam_identities(id int,user_id uuid);
        CREATE TEMP TABLE iam_groups(id int,name varchar(128));
        CREATE TEMP TABLE iam_group_members(group_id int,identity_id int);
        CREATE TEMP TABLE organizations(id uuid,is_active bool);
        CREATE TEMP TABLE user_organizations(user_id uuid,organization_id uuid);
        CREATE TEMP TABLE oauth_clients(client_id text, active bool, registration_source text, access_token_audience text);
        CREATE TEMP TABLE client_role_permissions(client_id text,role_key text,permission_key text);
        INSERT INTO oauth_clients VALUES ('shared',true,'admin','api'), ('dynamic',true,'dynamic','api'),('disabled',false,'admin','api');
        INSERT INTO client_role_permissions VALUES ('app','member','read'), ('shared','reviewer','approve'),
            ('dynamic','admin','configure'),('disabled','owner','write');
        INSERT INTO iam_groups VALUES (1,'rp:app:member'),(2,'rp:dynamic:admin'),(3,'rp:disabled:owner'),
            (4,'ordinary'),(5,'rp:app:BAD'),(6,'rp:shared:reviewer@invalid');
        INSERT INTO iam_group_members SELECT n,1 FROM generate_series(1,8) n")
        .execute(&mut *tx).await.unwrap();
    let user = Uuid::new_v4();
    let org = Uuid::new_v4();
    sqlx::query("INSERT INTO users VALUES ($1)")
        .bind(user)
        .execute(&mut *tx)
        .await
        .unwrap();
    let empty = resolve(&mut tx, user, "app", Some("api"))
        .await
        .unwrap()
        .unwrap();
    assert!(empty.roles.global.is_empty());
    assert!(empty.permissions.unwrap().global.is_empty());
    sqlx::query("INSERT INTO iam_identities VALUES (1,$1)")
        .bind(user)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations VALUES ($1,true)")
        .bind(org)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_organizations VALUES ($1,$2)")
        .bind(user)
        .bind(org)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO iam_groups VALUES (7,$1),(8,$2)")
        .bind(format!("rp:shared:reviewer@{org}"))
        .bind(format!("rp:app:member@{}", Uuid::new_v4()))
        .execute(&mut *tx)
        .await
        .unwrap();
    let snapshot = resolve(&mut tx, user, "app", Some("api"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot.roles.global,
        ["app:member", "disabled:owner", "dynamic:admin"]
    );
    assert_eq!(snapshot.roles.organizations.len(), 1);
    assert_eq!(
        snapshot.roles.organizations[&org.to_string()],
        ["shared:reviewer"]
    );
    let permissions = snapshot.permissions.unwrap();
    assert_eq!(permissions.global, ["read"]);
    assert_eq!(permissions.organizations[&org.to_string()], ["approve"]);
    let own = resolve(&mut tx, user, "app", None).await.unwrap().unwrap();
    assert!(own.permissions.unwrap().organizations.is_empty());
    sqlx::query("UPDATE organizations SET is_active=false")
        .execute(&mut *tx)
        .await
        .unwrap();
    let inactive = resolve(&mut tx, user, "app", Some("api"))
        .await
        .unwrap()
        .unwrap();
    assert!(inactive.roles.organizations.is_empty());
    sqlx::query("ALTER TABLE pg_temp.iam_groups RENAME COLUMN name TO unavailable")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(resolve(&mut tx, user, "app", None).await.unwrap().is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        1
    );
}
