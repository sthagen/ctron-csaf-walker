//! Walking through CSAF advisories
//!
//! ## Example
//!
//! A simple example for iterating over a source of CSAF documents:
//!
//! ```rust
//! use anyhow::Result;
//! use url::Url;
//! use csaf_walker::source::HttpSource;
//! use csaf_walker::walker::Walker;
//! use csaf_walker::retrieve::RetrievingVisitor;
//! use csaf_walker::validation::{ValidatedAdvisory, ValidationError, ValidationVisitor};
//! use walker_common::fetcher::Fetcher;
//!
//! async fn walk() -> Result<()> {
//!   let fetcher = Fetcher::new(Default::default()).await?;
//!   let source = HttpSource {
//!     url: Url::parse("https://www.redhat.com/.well-known/csaf/provider-metadata.json")?,
//!     options: Default::default(),
//!     fetcher,
//!   };
//!
//!   Walker::new(source.clone())
//!     .walk(RetrievingVisitor::new(
//!         source.clone(),
//!         ValidationVisitor::new(
//!             move |advisory: Result<ValidatedAdvisory, ValidationError>| async move {
//!                 log::info!("Found advisory: {advisory:?}");
//!                 Ok::<_, anyhow::Error>(())
//!             },
//!         )
//!     ))
//!     .await?;
//!
//!   Ok(())
//! }
//! ```

pub mod discover;
pub mod model;
pub mod retrieve;
pub mod source;
pub mod validation;
pub mod visitors;
pub mod walker;