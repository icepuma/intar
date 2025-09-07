//! Embedded quotes loader for the TUI header.
//!
//! Parses a compile-time embedded JSON file (`assets/quotes.json`) and
//! provides a helper to select a random quote for display in the run UI.

use rand::prelude::IndexedRandom;
use serde::Deserialize;

/// A single quote entry.
#[derive(Debug, Deserialize)]
struct QuoteEntry {
    person: String,
    quote: String,
}

/// Return a random quote as (quote, person) if available.
///
/// # Errors
/// This function silently returns `None` if parsing fails or no quotes exist.
#[must_use]
pub fn random_quote() -> Option<(String, String)> {
    // Embed the quotes JSON at compile-time
    const QUOTES_JSON: &str = include_str!("../../assets/quotes.json");
    let entries: Vec<QuoteEntry> = serde_json::from_str(QUOTES_JSON).ok()?;
    let mut rng = rand::rng();
    let picked = entries.choose(&mut rng)?;
    Some((picked.quote.clone(), picked.person.clone()))
}
