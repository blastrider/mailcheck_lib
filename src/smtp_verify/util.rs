use rand::{Rng, distributions::Alphanumeric};

use crate::smtp_verify::types::Existence;

pub fn random_local_part(len: usize) -> String {
    let length = len.clamp(6, 32);
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub fn confidence_for(existence: &Existence) -> f32 {
    match existence {
        Existence::Exists => 0.95,
        Existence::DoesNotExist => 0.95,
        Existence::CatchAll => 0.7,
        Existence::Indeterminate(_) => 0.4,
    }
}
