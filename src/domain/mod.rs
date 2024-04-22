mod api;
mod core;
mod db;

pub use crate::domain::{
    api::DomainApi,
    core::{domain_read, Domain},
    db::domain_select,
};
