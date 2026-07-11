use sea_orm::entity::prelude::*;

/// Users table — stores account information.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub uuid: String,
    /// Discord user ID (snowflake) — used to detect returning registrations.
    #[sea_orm(column_type = "Text", unique)]
    pub discord_id: String,
    /// AES-256 key (32 bytes) stored as binary.
    pub aes_key: Vec<u8>,
    /// Discord OAuth2 access token.
    pub access_token: String,
    /// Discord OAuth2 refresh token.
    pub refresh_token: String,
    /// Unix timestamp (seconds) when the access token expires.
    pub token_expires_at: i64,
    /// Unix timestamp (seconds) when the account was created.
    pub created_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}