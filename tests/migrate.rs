#[cfg(feature = "postgres")]
#[test]
fn migrations_postgres() {
    use diesel::Connection;
    if let Ok(url) = std::env::var("DATABASE_URL") {
        if diesel::pg::PgConnection::establish(&url).is_ok() {
            risu_rs::migrate::run(&url, "postgres", true, true).unwrap();
        }
    }
}

#[cfg(feature = "mysql")]
#[test]
fn migrations_mysql() {
    use diesel::Connection;
    if let Ok(url) = std::env::var("DATABASE_URL") {
        if diesel::mysql::MysqlConnection::establish(&url).is_ok() {
            risu_rs::migrate::run(&url, "mysql", true, true).unwrap();
        }
    }
}
