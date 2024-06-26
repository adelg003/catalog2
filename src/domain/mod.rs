mod api;
mod core;
mod db;
mod page;
mod util;

pub use crate::domain::{api::DomainApi, db::domain_select, page::route};
