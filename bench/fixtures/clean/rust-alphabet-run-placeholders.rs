// False positive class found by scanning a public Rust monorepo (1.4.7).
//
// Every value here is a hand-typed alphabet run. Shannon entropy counts how
// often each character occurs and throws the order away, so a strict run uses
// every character exactly once and scores at the TOP of the range for its
// length: each of these clears the 3.5 bits/char entropy gate comfortably.
// Only the sequential-run check drops them. None is a credential.
//
// Deliberately no vendor prefixes in this file. The run check applies to
// vendor-anchored rules too, and that half of it matters more, but a committed
// file carrying a complete provider-key shape trips credential scanners no
// matter how synthetic the value is. That half is covered by fragment-built
// values in packages/core's sequential-run tests instead; this file guards the
// generic rules, which is also where the real-world instances were found.
//
// The bindings below are written without type annotations on purpose: the
// generic rules anchor on `<keyword> = <value>`, and `NAME: &str = "…"` puts a
// type where they expect the value.

// bearer-token is prefix-anchored, so a constant is fine here. The literal
// "Bearer " dilutes run coverage but not below the threshold.
const AUTHORIZATION: &str = "Bearer abcdefghijklmnopqrstuvwxyz0123456789";

fn placeholders() -> Vec<String> {
    // api-key-generic: ascending letters, then ascending digits.
    let api_key = "abcdefghijklmnopqrstuvwxyz0123456789";
    let ascending = api_key.to_string();

    // api-key-generic: digits first, then letters.
    let api_key = "0123456789abcdefghijklmnopqrstuvwxyz";
    let digits_first = api_key.to_string();

    // api-key-generic: the same run written backwards.
    let api_key = "zyxwvutsrqponmlkjihgfedcba9876543210";
    let descending = api_key.to_string();

    // api-key-generic: several separate runs, so no single long sweep carries it.
    let api_key = "abcdefghij0123456789klmnopqrstuvwxyz";
    let mixed_runs = api_key.to_string();

    // secret-generic reads the same shape through a different keyword.
    let secret = "0123456789abcdefghijklmnopqrstuvwxyz";

    vec![
        ascending,
        digits_first,
        descending,
        mixed_runs,
        secret.to_string(),
        AUTHORIZATION.to_string(),
    ]
}
