use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, Database, DatabaseConnection, DbErr,
    EntityTrait, QueryFilter, Set, Statement,
};
use uuid::Uuid;

use crate::models;

/// Initialize the database connection and ensure the users table exists.
pub async fn init_database(url: &str) -> Result<DatabaseConnection, DbErr> {
    let db = Database::connect(url).await?;

    // Create the users table if it doesn't exist
    // We use a raw SQL statement for SQLite compatibility
    let sql = r#"
        CREATE TABLE IF NOT EXISTS users (
            uuid TEXT PRIMARY KEY,
            discord_id TEXT NOT NULL UNIQUE,
            aes_key BLOB NOT NULL,
            access_token TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            token_expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        )
    "#;

    db.execute(Statement::from_string(
        db.get_database_backend(),
        sql,
    ))
    .await?;

    Ok(db)
}

/// Create a new user in the database.
pub async fn create_user(
    db: &DatabaseConnection,
    uuid: &Uuid,
    discord_id: &str,
    aes_key: &[u8],
    access_token: &str,
    refresh_token: &str,
    token_expires_at: i64,
    created_at: i64,
) -> Result<(), DbErr> {
    let user = models::ActiveModel {
        uuid: Set(uuid.to_string()),
        discord_id: Set(discord_id.to_string()),
        aes_key: Set(aes_key.to_vec()),
        access_token: Set(access_token.to_string()),
        refresh_token: Set(refresh_token.to_string()),
        token_expires_at: Set(token_expires_at),
        created_at: Set(created_at),
    };
    user.insert(db).await?;
    Ok(())
}

/// Find a user by their Discord snowflake ID.
pub async fn get_user_by_discord_id(
    db: &DatabaseConnection,
    discord_id: &str,
) -> Result<Option<models::Model>, DbErr> {
    models::Entity::find()
        .filter(models::Column::DiscordId.eq(discord_id))
        .one(db)
        .await
}

/// Retrieve a user by their UUID.
pub async fn get_user_by_uuid(
    db: &DatabaseConnection,
    uuid: &Uuid,
) -> Result<Option<models::Model>, DbErr> {
    models::Entity::find()
        .filter(models::Column::Uuid.eq(uuid.to_string()))
        .one(db)
        .await
}

/// Update the OAuth2 tokens for a user.
pub async fn update_user_tokens(
    db: &DatabaseConnection,
    uuid: &Uuid,
    access_token: &str,
    refresh_token: &str,
    token_expires_at: i64,
) -> Result<(), DbErr> {
    let user: Option<models::Model> = models::Entity::find()
        .filter(models::Column::Uuid.eq(uuid.to_string()))
        .one(db)
        .await?;

    if let Some(user) = user {
        let mut active: models::ActiveModel = user.into();
        active.access_token = Set(access_token.to_string());
        active.refresh_token = Set(refresh_token.to_string());
        active.token_expires_at = Set(token_expires_at);
        active.update(db).await?;
    }

    Ok(())
}

/// Get all users (used by token refresh background task).
pub async fn get_all_users(db: &DatabaseConnection) -> Result<Vec<models::Model>, DbErr> {
    models::Entity::find().all(db).await
}

/// Get users whose token is about to expire (within the given margin in seconds).
pub async fn get_users_needing_refresh(
    db: &DatabaseConnection,
    margin_secs: i64,
) -> Result<Vec<models::Model>, DbErr> {
    let now = chrono::Utc::now().timestamp();
    let threshold = now + margin_secs;

    models::Entity::find()
        .filter(models::Column::TokenExpiresAt.lte(threshold))
        .all(db)
        .await
}