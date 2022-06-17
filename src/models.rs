use tokio_postgres::Row;

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct CasbinRule {
    pub id: i32,
    pub ptype: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: String,
    pub v4: String,
    pub v5: String,
}

impl From<Row> for CasbinRule {
    fn from(row: Row) -> Self {
        Self {
            id: row.get("id"),
            ptype: row.get("ptype"),
            v0: row.get("v0"),
            v1: row.get("v1"),
            v2: row.get("v2"),
            v3: row.get("v3"),
            v4: row.get("v4"),
            v5: row.get("v5"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct NewCasbinRule<'a> {
    pub ptype: &'a str,
    pub v0: &'a str,
    pub v1: &'a str,
    pub v2: &'a str,
    pub v3: &'a str,
    pub v4: &'a str,
    pub v5: &'a str,
}
