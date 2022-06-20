#![allow(clippy::suspicious_else_formatting)]
#![allow(clippy::toplevel_ref_arg)]
use crate::models::{CasbinRule, NewCasbinRule};
use crate::Error;
use casbin::{error::AdapterError, Error as CasbinError, Filter, Result};
use deadpool_postgres::Pool;
use futures::try_join;
use tokio_postgres::{types::Type, SimpleQueryMessage};

pub type ConnectionPool = Pool;

pub async fn new(conn: &ConnectionPool) -> Result<Vec<SimpleQueryMessage>> {
    let client = conn
        .get()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

    client
        .simple_query(
            "CREATE TABLE IF NOT EXISTS casbin_rule (
                    id SERIAL PRIMARY KEY,
                    ptype VARCHAR NOT NULL,
                    v0 VARCHAR NOT NULL,
                    v1 VARCHAR NOT NULL,
                    v2 VARCHAR NOT NULL,
                    v3 VARCHAR NOT NULL,
                    v4 VARCHAR NOT NULL,
                    v5 VARCHAR NOT NULL,
                    CONSTRAINT unique_key_pg_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                    )
        ",
        )
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))
}

pub async fn remove_policy(conn: &ConnectionPool, pt: &str, rule: Vec<String>) -> Result<bool> {
    let rule = normalize_casbin_rule(rule);
    let client = conn
        .get()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

    let stmt = client
        .prepare_typed(
            "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    v0 = $2 AND
                    v1 = $3 AND
                    v2 = $4 AND
                    v3 = $5 AND
                    v4 = $6 AND
                    v5 = $7
              RETURNING id",
            &[
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
            ],
        )
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    client
        .query_opt(
            &stmt,
            &[
                &pt, &rule[0], &rule[1], &rule[2], &rule[3], &rule[4], &rule[5],
            ],
        )
        .await
        .map(|s| s.is_some())
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))
}

pub async fn remove_policies(
    conn: &ConnectionPool,
    pt: &str,
    rules: Vec<Vec<String>>,
) -> Result<bool> {
    let mut client = conn
        .get()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

    let stmt = client
        .prepare_typed(
            "DELETE FROM casbin_rule WHERE
                ptype = $1 AND
                v0 = $2 AND
                v1 = $3 AND
                v2 = $4 AND
                v3 = $5 AND
                v4 = $6 AND
                v5 = $7
              RETURNING id",
            &[
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
            ],
        )
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    let transaction = client
        .transaction()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    for rule in rules {
        let rule = normalize_casbin_rule(rule);
        transaction
            .query_one(
                &stmt,
                &[
                    &pt, &rule[0], &rule[1], &rule[2], &rule[3], &rule[4], &rule[5],
                ],
            )
            .await
            .map(|s| s.is_empty())
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    }
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    Ok(true)
}

pub async fn remove_filtered_policy(
    conn: &ConnectionPool,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    let client = conn
        .get()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

    let field_values = normalize_casbin_rule(field_values);
    if field_index == 5 {
        let stmt = client
            .prepare_typed(
                "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v5 is NULL OR v5 = $2)
                  RETURNING id",
                &[Type::TEXT, Type::TEXT],
            )
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
        client
            .query_opt(&stmt, &[&pt, &field_values[5]])
            .await
            .map(|s| s.is_some())
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))
    } else if field_index == 4 {
        let stmt = client
            .prepare_typed(
                "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v4 is NULL OR v4 = $2) AND
                    (v5 is NULL OR v5 = $3)
                  RETURNING id",
                &[Type::TEXT, Type::TEXT, Type::TEXT],
            )
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
        client
            .query_opt(&stmt, &[&pt, &field_values[4], &field_values[5]])
            .await
            .map(|s| s.is_some())
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))
    } else if field_index == 3 {
        let stmt = client
            .prepare_typed(
                "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v3 is NULL OR v3 = $2) AND
                    (v4 is NULL OR v4 = $3) AND
                    (v5 is NULL OR v5 = $4)
                  RETURNING id",
                &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
            )
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
        client
            .query_opt(
                &stmt,
                &[&pt, &field_values[3], &field_values[4], &field_values[5]],
            )
            .await
            .map(|s| s.is_some())
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))
    } else if field_index == 2 {
        let stmt = client
            .prepare_typed(
                "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v2 is NULL OR v2 = $2) AND
                    (v3 is NULL OR v3 = $3) AND
                    (v4 is NULL OR v4 = $4) AND
                    (v5 is NULL OR v5 = $5)
                  RETURNING id",
                &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
            )
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
        client
            .query_opt(
                &stmt,
                &[
                    &pt,
                    &field_values[2],
                    &field_values[3],
                    &field_values[4],
                    &field_values[5],
                ],
            )
            .await
            .map(|s| s.is_some())
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))
    } else if field_index == 1 {
        let stmt = client
            .prepare_typed(
                "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v1 is NULL OR v1 = $2) AND
                    (v2 is NULL OR v2 = $3) AND
                    (v3 is NULL OR v3 = $4) AND
                    (v4 is NULL OR v4 = $5) AND
                    (v5 is NULL OR v5 = $6)
                  RETURNING id",
                &[
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                ],
            )
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
        client
            .query_opt(
                &stmt,
                &[
                    &pt,
                    &field_values[1],
                    &field_values[2],
                    &field_values[3],
                    &field_values[4],
                    &field_values[5],
                ],
            )
            .await
            .map(|s| s.is_some())
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))
    } else {
        let stmt = client
            .prepare_typed(
                "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v0 is NULL OR v0 = $2) AND
                    (v1 is NULL OR v1 = $3) AND
                    (v2 is NULL OR v2 = $4) AND
                    (v3 is NULL OR v3 = $5) AND
                    (v4 is NULL OR v4 = $6) AND
                    (v5 is NULL OR v5 = $7)
                  RETURNING id",
                &[
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                    Type::TEXT,
                ],
            )
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;

        client
            .query_opt(
                &stmt,
                &[
                    &pt,
                    &field_values[0],
                    &field_values[1],
                    &field_values[2],
                    &field_values[3],
                    &field_values[4],
                    &field_values[5],
                ],
            )
            .await
            .map(|s| s.is_some())
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))
    }
}

pub(crate) async fn load_policy(conn: &ConnectionPool) -> Result<Vec<CasbinRule>> {
    let client = conn
        .get()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

    let stmt = client
        .prepare_typed("SELECT * FROM casbin_rule", &[])
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    let casbin_rule: Vec<CasbinRule> = client
        .query(&stmt, &[])
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?
        .into_iter()
        .map(CasbinRule::from)
        .collect();
    Ok(casbin_rule)
}

pub(crate) async fn load_filtered_policy<'a>(
    conn: &ConnectionPool,
    filter: &Filter<'_>,
) -> Result<Vec<CasbinRule>> {
    let client = conn
        .get()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

    let (g_filter, p_filter) = filtered_where_values(filter);

    let stmt = client
        .prepare_typed("SELECT * from casbin_rule WHERE (
            ptype LIKE 'g%' AND v0 LIKE $1 AND v1 LIKE $2 AND v2 LIKE $3 AND v3 LIKE $4 AND v4 LIKE $5 AND v5 LIKE $6 )
        OR (
            ptype LIKE 'p%' AND v0 LIKE $7 AND v1 LIKE $8 AND v2 LIKE $9 AND v3 LIKE $10 AND v4 LIKE $11 AND v5 LIKE $12 )", &[
            Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT,
            Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT,
            ])
        .await
        .map_err(|err| {
            CasbinError::from(AdapterError(Box::new(Error::PostgresError(
                err,
            ))))
        })?;
    let casbin_rule: Vec<CasbinRule> = client
        .query(
            &stmt,
            &[
                &g_filter[0],
                &g_filter[1],
                &g_filter[2],
                &g_filter[3],
                &g_filter[4],
                &g_filter[5],
                &p_filter[0],
                &p_filter[1],
                &p_filter[2],
                &p_filter[3],
                &p_filter[4],
                &p_filter[5],
            ],
        )
        .await
        // .map(|s| s.into())
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?
        .into_iter()
        .map(CasbinRule::from)
        .collect();

    Ok(casbin_rule)
}

fn filtered_where_values<'a>(filter: &Filter<'a>) -> ([&'a str; 6], [&'a str; 6]) {
    let mut g_filter: [&'a str; 6] = ["%", "%", "%", "%", "%", "%"];
    let mut p_filter: [&'a str; 6] = ["%", "%", "%", "%", "%", "%"];
    for (idx, val) in filter.g.iter().enumerate() {
        if val != &"" {
            g_filter[idx] = val;
        }
    }
    for (idx, val) in filter.p.iter().enumerate() {
        if val != &"" {
            p_filter[idx] = val;
        }
    }
    (g_filter, p_filter)
}

pub(crate) async fn save_policy(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'_>>,
) -> Result<()> {
    let mut client = conn
        .get()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;
    let (stmt_delete, stmt_insert) = try_join!(
        client.prepare_typed("DELETE FROM casbin_rule", &[]),
        client.prepare_typed(
            "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 ) RETURNING id",
            &[
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
            ],
        ),
    )
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;

    let transaction = client
        .transaction()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;

    transaction
        .query(&stmt_delete, &[])
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;

    for rule in rules {
        transaction
            .query_one(
                &stmt_insert,
                &[
                    &rule.ptype,
                    &rule.v0,
                    &rule.v1,
                    &rule.v2,
                    &rule.v3,
                    &rule.v4,
                    &rule.v5,
                ],
            )
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    }
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    Ok(())
}

pub(crate) async fn add_policy(conn: &ConnectionPool, rule: NewCasbinRule<'_>) -> Result<bool> {
    let client = conn
        .get()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;
    let stmt = client
        .prepare_typed(
            "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )
              RETURNING id",
            &[
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
            ],
        )
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    client
        .query_one(
            &stmt,
            &[
                &rule.ptype,
                &rule.v0,
                &rule.v1,
                &rule.v2,
                &rule.v3,
                &rule.v4,
                &rule.v5,
            ],
        )
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;

    Ok(true)
}

pub(crate) async fn add_policies(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'_>>,
) -> Result<bool> {
    let mut client = conn
        .get()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

    let stmt = client
        .prepare_typed(
            "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )
              RETURNING id",
            &[
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
            ],
        )
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;

    let transaction = client
        .transaction()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    for rule in rules {
        transaction
            .query_one(
                &stmt,
                &[
                    &rule.ptype,
                    &rule.v0,
                    &rule.v1,
                    &rule.v2,
                    &rule.v3,
                    &rule.v4,
                    &rule.v5,
                ],
            )
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    }
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    Ok(true)
}

pub(crate) async fn clear_policy(conn: &ConnectionPool) -> Result<()> {
    let mut client = conn
        .get()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

    let stmt = client
        .prepare_typed("DELETE FROM casbin_rule", &[])
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;

    let transaction = client
        .transaction()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    transaction
        .query(&stmt, &[])
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;

    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PostgresError(err)))))?;
    Ok(())
}

fn normalize_casbin_rule(mut rule: Vec<String>) -> Vec<String> {
    rule.resize(6, String::new());
    rule
}
