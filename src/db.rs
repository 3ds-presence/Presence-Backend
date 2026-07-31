// 3DS Presence — Discord Rich Presence for Nintendo 3DS
// Copyright (C) 2026 3DS Presence - LeonLeBreton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, Database, DatabaseConnection, DbErr,
    EntityTrait, QueryFilter, Schema, Set,
};
use uuid::Uuid;

use crate::models;
use crate::crypto;

/// Parameters for creating a new user.
pub struct CreateUserParams<'a> {
    pub db: &'a DatabaseConnection,
    /// Master key used to encrypt the secrets below at rest (AES-256-GCM).
    pub master_key: &'a [u8; 32],
    pub uuid: &'a Uuid,
    pub discord_id: &'a str,
    pub aes_key: &'a [u8],
    pub access_token: &'a str,
    pub refresh_token: &'a str,
    pub token_expires_at: i64,
    pub created_at: i64,
}

/// Initialize the database connection and ensure the users table exists.
pub async fn init_database(url: &str) -> Result<DatabaseConnection, DbErr> {
    let db = Database::connect(url).await?;

    // Create the users table from the entity definition
    let backend = db.get_database_backend();
    let schema = Schema::new(backend);
    let mut create_stmt = schema.create_table_from_entity(models::Entity);
    create_stmt.if_not_exists();
    let stmt = backend.build(&create_stmt);
    db.execute(stmt).await?;

    Ok(db)
}

/// Create a new user in the database.
pub async fn create_user(params: CreateUserParams<'_>) -> Result<(), DbErr> {
    let user = models::ActiveModel {
        uuid: Set(params.uuid.to_string()),
        discord_id: Set(params.discord_id.to_string()),
        aes_key: Set(crypto::encrypt_bytes_at_rest(params.aes_key, params.master_key)),
        access_token: Set(crypto::encrypt_string_at_rest(params.access_token, params.master_key)),
        refresh_token: Set(crypto::encrypt_string_at_rest(params.refresh_token, params.master_key)),
        token_expires_at: Set(params.token_expires_at),
        created_at: Set(params.created_at),
        last_connected: Set(params.created_at),
    };
    user.insert(params.db).await?;
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

/// Update the `OAuth2` tokens for a user.
pub async fn update_user_tokens(
    db: &DatabaseConnection,
    master_key: &[u8; crypto::MASTER_KEY_LEN],
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
        active.access_token = Set(crypto::encrypt_string_at_rest(access_token, master_key));
        active.refresh_token = Set(crypto::encrypt_string_at_rest(refresh_token, master_key));
        active.token_expires_at = Set(token_expires_at);
        active.update(db).await?;
    }

    Ok(())
}

/// Update the AES-256 key for a user.
pub async fn update_user_aes_key(
    db: &DatabaseConnection,
    master_key: &[u8; crypto::MASTER_KEY_LEN],
    uuid: &Uuid,
    new_aes_key: &[u8],
) -> Result<(), DbErr> {
    let user: Option<models::Model> = models::Entity::find()
        .filter(models::Column::Uuid.eq(uuid.to_string()))
        .one(db)
        .await?;

    if let Some(user) = user {
        let mut active: models::ActiveModel = user.into();
        active.aes_key = Set(crypto::encrypt_bytes_at_rest(new_aes_key, master_key));
        active.update(db).await?;
    }

    Ok(())
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

/// Delete a user by UUID.
pub async fn delete_user(db: &DatabaseConnection, uuid: &Uuid) -> Result<(), DbErr> {
    models::Entity::delete_many()
        .filter(models::Column::Uuid.eq(uuid.to_string()))
        .exec(db)
        .await?;
    Ok(())
}

/// Update the `last_connected` timestamp for a user.
pub async fn update_user_last_connected(
    db: &DatabaseConnection,
    uuid: &Uuid,
    now: i64,
) -> Result<(), DbErr> {
    let user: Option<models::Model> = models::Entity::find()
        .filter(models::Column::Uuid.eq(uuid.to_string()))
        .one(db)
        .await?;

    if let Some(user) = user {
        let mut active: models::ActiveModel = user.into();
        active.last_connected = Set(now);
        active.update(db).await?;
    }

    Ok(())
}

/// Delete users inactive for more than the given number of seconds.
pub async fn delete_inactive_users(
    db: &DatabaseConnection,
    inactive_threshold_secs: i64,
) -> Result<u64, DbErr> {
    let cutoff = chrono::Utc::now().timestamp() - inactive_threshold_secs;
    let result = models::Entity::delete_many()
        .filter(models::Column::LastConnected.lt(cutoff))
        .exec(db)
        .await?;
    Ok(result.rows_affected)
}
