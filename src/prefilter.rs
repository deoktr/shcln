use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

use crate::pattern_data::{
    ALWAYS_EVALUATE, KEYWORDS, KEYWORD_OFFSETS, KEYWORD_PATTERNS, PATTERN_COUNT,
};

/// Number of pattern slots covered by the stack buffers in [`Prefilter`].
/// The generated pattern list has fewer entries; the assertion in
/// [`Prefilter::new`] keeps the two in sync.
const MAX_PATTERNS: usize = 1024;
const MAX_WORDS: usize = MAX_PATTERNS / 64;

/// A cheap first pass that tells us which patterns could possibly match a
/// line. Patterns are only compiled and run when one of their required literal
/// keywords occurs in the line, which keeps a clean shell history from
/// compiling all of them at startup.
pub struct Prefilter {
    ac: AhoCorasick,
}

impl Prefilter {
    pub fn new() -> Self {
        assert!(PATTERN_COUNT <= MAX_PATTERNS);

        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(KEYWORDS)
            .expect("valid secret scanning keyword set");

        Self { ac }
    }

    /// Return the lowest-index pattern that matches `haystack`, using `check`
    /// to decide whether a candidate actually matches.
    pub fn find_match<F>(&self, haystack: &[u8], mut check: F) -> Option<usize>
    where
        F: FnMut(usize) -> bool,
    {
        let mut candidates = [0u16; MAX_PATTERNS];
        let count = self.collect_candidates(haystack, &mut candidates);

        for &pattern in &candidates[..count] {
            let pattern = pattern as usize;
            if check(pattern) {
                return Some(pattern);
            }
        }

        None
    }

    fn collect_candidates(&self, haystack: &[u8], out: &mut [u16; MAX_PATTERNS]) -> usize {
        let mut seen = [0u64; MAX_WORDS];
        let mut count = 0;

        for m in self.ac.find_overlapping_iter(haystack) {
            let keyword = m.pattern().as_usize();
            let start = KEYWORD_OFFSETS[keyword] as usize;
            let end = KEYWORD_OFFSETS[keyword + 1] as usize;

            for &pattern in &KEYWORD_PATTERNS[start..end] {
                if mark_seen(&mut seen, pattern as usize) {
                    out[count] = pattern;
                    count += 1;
                }
            }
        }

        for &pattern in &ALWAYS_EVALUATE {
            if mark_seen(&mut seen, pattern as usize) {
                out[count] = pattern;
                count += 1;
            }
        }

        out[..count].sort_unstable();
        count
    }

    #[cfg(test)]
    pub fn candidate_indices(&self, haystack: &[u8]) -> Vec<usize> {
        let mut candidates = [0u16; MAX_PATTERNS];
        let count = self.collect_candidates(haystack, &mut candidates);
        candidates[..count]
            .iter()
            .map(|&pattern| pattern as usize)
            .collect()
    }

    #[cfg(test)]
    pub fn pattern_count(&self) -> usize {
        PATTERN_COUNT
    }
}

fn mark_seen(seen: &mut [u64; MAX_WORDS], pattern: usize) -> bool {
    let word = pattern / 64;
    let bit = 1u64 << (pattern % 64);
    if seen[word] & bit != 0 {
        return false;
    }
    seen[word] |= bit;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefilter_covers_the_generated_pattern_list() {
        let prefilter = Prefilter::new();
        assert_eq!(prefilter.pattern_count(), PATTERN_COUNT);
    }

    #[test]
    fn benign_line_has_few_candidates() {
        let prefilter = Prefilter::new();
        assert!(prefilter.candidate_indices(b"cargo build --release").len() < PATTERN_COUNT / 2);
    }
}
