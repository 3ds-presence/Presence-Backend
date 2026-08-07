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

use sea_orm::DatabaseConnection;
use tokio::time::{sleep, Duration};

use crate::db;

/// Number of seconds in 3 years.
const THREE_YEARS_SECS: i64 = 3 * 365 * 24 * 60 * 60;

/// Run the cleanup task in a loop, deleting inactive accounts every 24 hours.
pub async fn run(db: DatabaseConnection) {
    loop {
        sleep(Duration::from_hours(24)).await;

        log::info!("evt=cleanup_started threshold_years=3");
        match db::delete_inactive_users(&db, THREE_YEARS_SECS).await {
            Ok(count) if count > 0 => {
                log::info!("evt=cleanup_complete count={count}");
            }
            Ok(_) => {}
            Err(e) => {
                log::error!("evt=cleanup_failed error={e}");
            }
        }
    }
}
