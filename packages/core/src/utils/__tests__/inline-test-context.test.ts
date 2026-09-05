import { findInlineTestRegions, isInsideInlineTestRegion } from '../inline-test-context';

/** Offset of the first occurrence of `needle` in `src`. */
function at(src: string, needle: string): number {
  const i = src.indexOf(needle);
  if (i === -1) throw new Error(`fixture does not contain ${needle}`);
  return i;
}

describe('findInlineTestRegions for Rust', () => {
  it('opens a region at a top-level cfg(test) module and runs to end of file', () => {
    const src = [
      'pub fn build() -> Client {',
      '    Client::new(PROD)',
      '}',
      '',
      '#[cfg(test)]',
      'mod tests {',
      '    const FIXTURE: &str = "value";',
      '}',
      '',
    ].join('\n');

    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(regions).toHaveLength(1);
    expect(isInsideInlineTestRegion(regions, at(src, 'Client::new'))).toBe(false);
    expect(isInsideInlineTestRegion(regions, at(src, 'FIXTURE'))).toBe(true);
  });

  it('opens a region for a cfg(test) function as well as a module', () => {
    const src = ['#[cfg(test)]', 'pub fn helper() {', '    let v = "value";', '}', ''].join('\n');
    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(isInsideInlineTestRegion(regions, at(src, '"value"'))).toBe(true);
  });

  it('accepts cfg(all(test, ...)) and cfg(any(test, ...))', () => {
    const src = ['#[cfg(all(test, unix))]', 'mod tests {', '    const F: &str = "value";', '}', ''].join('\n');
    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(isInsideInlineTestRegion(regions, at(src, '"value"'))).toBe(true);
  });

  it('accepts cfg(any(test, doc))', () => {
    const src = ['#[cfg(any(test, doc))]', 'mod tests {', '    const F: &str = "value";', '}', ''].join('\n');
    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(isInsideInlineTestRegion(regions, at(src, '"value"'))).toBe(true);
  });

  it('does not open a region for cfg(not(test))', () => {
    const src = ['#[cfg(not(test))]', 'mod prod {', '    const F: &str = "value";', '}', ''].join('\n');
    expect(findInlineTestRegions(src, 'src/client.rs')).toHaveLength(0);
  });

  // A negated `test` is a production-only marker in every shape it takes, not
  // only the bare `not(test)`. Treating `all(not(test), …)` as a test region
  // demoted a real credential in production code.
  it('does not open a region for a nested negated test predicate', () => {
    const src = [
      '#[cfg(all(not(test), feature = "prod"))]',
      'mod prod {',
      '    const F: &str = "value";',
      '}',
      '',
    ].join('\n');
    expect(findInlineTestRegions(src, 'src/client.rs')).toHaveLength(0);
  });

  it('closes an open region at a nested negated test predicate', () => {
    const src = [
      '#[cfg(test)]',
      'mod tests {',
      '    const IN_REGION: &str = "a";',
      '}',
      '',
      '#[cfg(any(not(test), doc))]',
      'mod prod {',
      '    const OUT_OF_REGION: &str = "b";',
      '}',
      '',
    ].join('\n');
    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(isInsideInlineTestRegion(regions, at(src, 'IN_REGION'))).toBe(true);
    expect(isInsideInlineTestRegion(regions, at(src, 'OUT_OF_REGION'))).toBe(false);
  });

  // `test` inside a string literal is a feature name, not the test predicate.
  // `\btest\b` accepted `test-utils` because `-` is a word boundary, and
  // `test-utils` is a common feature name enabled in ordinary release builds.
  it('does not open a region for a feature named test-utils', () => {
    const src = [
      '#[cfg(feature = "test-utils")]',
      'mod helpers {',
      '    const F: &str = "value";',
      '}',
      '',
    ].join('\n');
    expect(findInlineTestRegions(src, 'src/client.rs')).toHaveLength(0);
  });

  it('does not open a region for a feature named testing', () => {
    const src = [
      '#[cfg(feature = "testing")]',
      'mod helpers {',
      '    const F: &str = "value";',
      '}',
      '',
    ].join('\n');
    expect(findInlineTestRegions(src, 'src/client.rs')).toHaveLength(0);
  });

  it('does not open a region for a feature literally named test', () => {
    const src = [
      '#[cfg(feature = "test")]',
      'mod helpers {',
      '    const F: &str = "value";',
      '}',
      '',
    ].join('\n');
    expect(findInlineTestRegions(src, 'src/client.rs')).toHaveLength(0);
  });

  it('still opens a region when test is combined with a negated feature', () => {
    const src = [
      '#[cfg(all(test, not(feature = "slow")))]',
      'mod tests {',
      '    const F: &str = "value";',
      '}',
      '',
    ].join('\n');
    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(isInsideInlineTestRegion(regions, at(src, '"value"'))).toBe(true);
  });

  it('closes the region at a following cfg(not(test)) item', () => {
    const src = [
      '#[cfg(test)]',
      'mod tests {',
      '    const IN_REGION: &str = "a";',
      '}',
      '',
      '#[cfg(not(test))]',
      'mod prod {',
      '    const OUT_OF_REGION: &str = "b";',
      '}',
      '',
    ].join('\n');
    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(isInsideInlineTestRegion(regions, at(src, 'IN_REGION'))).toBe(true);
    expect(isInsideInlineTestRegion(regions, at(src, 'OUT_OF_REGION'))).toBe(false);
  });

  it('closes the region at the next unannotated top-level item', () => {
    const src = [
      '#[cfg(test)]',
      'mod tests {',
      '    const IN_REGION: &str = "a";',
      '}',
      '',
      'pub struct Later {',
      '    field: &\'static str,',
      '}',
      '',
      'const OUT_OF_REGION: &str = "b";',
      '',
    ].join('\n');
    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(isInsideInlineTestRegion(regions, at(src, 'IN_REGION'))).toBe(true);
    expect(isInsideInlineTestRegion(regions, at(src, 'OUT_OF_REGION'))).toBe(false);
  });

  // A column-0 macro invocation is production code resuming. Without this the
  // region ran past `lazy_static! { … }` to end of file and demoted whatever
  // the macro body held.
  it('closes the region at a column-0 macro invocation', () => {
    const src = [
      '#[cfg(test)]',
      'mod tests {',
      '    const IN_REGION: &str = "a";',
      '}',
      '',
      'lazy_static! {',
      '    static ref OUT_OF_REGION: String = String::from("b");',
      '}',
      '',
    ].join('\n');
    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(isInsideInlineTestRegion(regions, at(src, 'IN_REGION'))).toBe(true);
    expect(isInsideInlineTestRegion(regions, at(src, 'OUT_OF_REGION'))).toBe(false);
  });

  it('closes the region at a path-qualified macro invocation', () => {
    const src = [
      '#[cfg(test)]',
      'mod tests {',
      '    const IN_REGION: &str = "a";',
      '}',
      '',
      'serde_json::json!({',
      '    "key": "OUT_OF_REGION"',
      '});',
      '',
    ].join('\n');
    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(isInsideInlineTestRegion(regions, at(src, 'IN_REGION'))).toBe(true);
    expect(isInsideInlineTestRegion(regions, at(src, 'OUT_OF_REGION'))).toBe(false);
  });

  it('keeps the region open across consecutive cfg(test) items', () => {
    const src = [
      '#[cfg(test)]',
      'mod error_tests;',
      '',
      '#[cfg(test)]',
      'mod tests {',
      '    const IN_REGION: &str = "a";',
      '}',
      '',
    ].join('\n');
    const regions = findInlineTestRegions(src, 'src/client.rs');
    expect(regions).toHaveLength(1);
    expect(isInsideInlineTestRegion(regions, at(src, 'IN_REGION'))).toBe(true);
  });

  it('ignores an indented cfg(test) attribute', () => {
    const src = [
      'impl Client {',
      '    #[cfg(test)]',
      '    pub fn probe(&self) {}',
      '',
      '    pub fn send(&self) {',
      '        let v = "value";',
      '    }',
      '}',
      '',
    ].join('\n');
    expect(findInlineTestRegions(src, 'src/client.rs')).toHaveLength(0);
  });

  it('returns nothing for a language with no registered finder', () => {
    const src = ['#[cfg(test)]', 'mod tests {', '    const F: &str = "a";', '}'].join('\n');
    expect(findInlineTestRegions(src, 'src/client.ts')).toHaveLength(0);
    expect(findInlineTestRegions(src, undefined)).toHaveLength(0);
  });

  it('returns nothing for a Rust file with no cfg(test) attribute', () => {
    const src = ['pub fn build() {', '    let v = "value";', '}', ''].join('\n');
    expect(findInlineTestRegions(src, 'src/client.rs')).toHaveLength(0);
  });
});
