# postgres-adapter

[![Crates.io](https://img.shields.io/crates/v/tokio-postgres.svg)](https://crates.io/crates/tokio-postgres)
[![Docs](https://docs.rs/tokio-postgres/badge.svg)](https://docs.rs/tokio-postgres)
[![Crates.io](https://img.shields.io/crates/v/deadpool-postgres.svg)](https://crates.io/crates/deadpool-postgres)
[![Docs](https://docs.rs/deadpool-postgres/badge.svg)](https://docs.rs/deadpool-postgres)

[![CI](https://github.com/casbin-rs/postgres-adapter/workflows/CI/badge.svg)](https://github.com/casbin-rs/postgres-adapter/actions)
[![codecov](https://codecov.io/gh/casbin-rs/postgres-adapter/branch/master/graph/badge.svg)](https://codecov.io/gh/casbin-rs/postgres-adapter)


postgres-adapter uses [tokio-postgres](https://github.com/sfackler/rust-postgres/tree/master/tokio-postgres) and [deadpool-postgres](https://github.com/bikeshedder/deadpool/tree/master/postgres) as an adapter for [Casbin-rs](https://github.com/casbin/casbin-rs). With this library, Casbin can load policy from [Postgres](https://github.com/lib/pq) or save policy to it with fully asynchronous support and prepared statements.

## Install

Add it to `Cargo.toml`

```rust
postgres-adapter = { version = "0.1.0" }
tokio = "1.19.2"
```

## Configure

1. Set up database environment    
    ```bash
    #!/bin/bash

    docker run -itd \
        --restart always \
        -e POSTGRES_USER=casbin_rs \
        -e POSTGRES_PASSWORD=casbin_rs \
        -e POSTGRES_DB=casbin \
        -p 5432:5432 \
        -v /srv/docker/postgresql:/var/lib/postgresql \
        postgres:11;
    ```

2. Create table `casbin_rule`

    ```bash
    # PostgreSQL
    psql postgres://casbin_rs:casbin_rs@127.0.0.1:5432/casbin -c "CREATE TABLE IF NOT EXISTS casbin_rule (
        id SERIAL PRIMARY KEY,
        ptype VARCHAR NOT NULL,
        v0 VARCHAR NOT NULL,
        v1 VARCHAR NOT NULL,
        v2 VARCHAR NOT NULL,
        v3 VARCHAR NOT NULL,
        v4 VARCHAR NOT NULL,
        v5 VARCHAR NOT NULL,
        CONSTRAINT unique_key_sqlx_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
        );"

3. Configure `env`

    Rename `sample.env` to `.env` and put `DATABASE_URL`, `POOL_SIZE`   inside

    ```bash
    DATABASE_URL=postgres://casbin_rs:casbin_rs@localhost:5432/casbin
    POOL_SIZE=8
    ```

    Or you can export `DATABASE_URL`, `POOL_SIZE`

    ```bash
    export DATABASE_URL=postgres://casbin_rs:casbin_rs@localhost:5432/casbin
    export POOL_SIZE=8
    ```


## Example

```rust
use postgres_adapter::casbin::prelude::*;
use postgres_adapter::casbin::Result;
use postgres_adapter::TokioPostgresAdapter;
use tokio_postgres::NoTls;

#[tokio::main]
async fn main() -> Result<()> {
    let m = DefaultModel::from_file("examples/rbac_model.conf").await?;
    
    let a = TokioPostgresAdapter::new("postgres://casbin_rs:casbin_rs@127.0.0.1:5432/casbin", 8, NoTls).await?;
    let mut e = Enforcer::new(m, a).await?;
    
    Ok(())
}

```

## Features

- `postgres`
