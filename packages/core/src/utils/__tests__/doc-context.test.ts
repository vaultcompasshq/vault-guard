import {
  isDocumentationPath,
  isAlgoliaSearchOnlyKey,
  shouldSuppressDocContextMatch,
} from '../doc-context';

describe('isDocumentationPath', () => {
  it('recognizes docs/ and website/ trees', () => {
    expect(isDocumentationPath('pydantic/docs/extra/algolia.js')).toBe(true);
    expect(isDocumentationPath('prettier/website/docusaurus.config.js')).toBe(true);
  });

  it('recognizes markdown under docs/', () => {
    expect(isDocumentationPath('gatsby/docs/tutorial/part-4/index.md')).toBe(true);
  });

  it('recognizes root README and CLAUDE markdown', () => {
    expect(isDocumentationPath('example-app/README.md')).toBe(true);
    expect(isDocumentationPath('example-app/CLAUDE.md')).toBe(true);
    expect(isDocumentationPath('example-app/POSTHOG_SETUP.md')).toBe(true);
  });

  it('does not mark production source', () => {
    expect(isDocumentationPath('src/config.ts')).toBe(false);
  });
});

describe('isAlgoliaSearchOnlyKey', () => {
  it('matches 32-char hex keys', () => {
    expect(isAlgoliaSearchOnlyKey('ecfff8a35d82ecff7e911d57d7be8510')).toBe(true);
  });

  it('rejects non-hex or wrong length', () => {
    expect(isAlgoliaSearchOnlyKey('not-a-real-api-key-value-here')).toBe(false);
    expect(isAlgoliaSearchOnlyKey('abc123')).toBe(false);
  });
});

describe('shouldSuppressDocContextMatch', () => {
  it('suppresses Algolia search keys in docs config', () => {
    const line = '  apiKey: "ecfff8a35d82ecff7e911d57d7be8510",';
    expect(
      shouldSuppressDocContextMatch(
        'api-key-generic',
        'prettier/website/docusaurus.config.js',
        'ecfff8a35d82ecff7e911d57d7be8510',
        line,
        line,
      ),
    ).toBe(true);
  });

  it('suppresses your_*_key placeholders in markdown docs', () => {
    expect(
      shouldSuppressDocContextMatch(
        'api-key-generic',
        'example-app/ANALYTICS_GUIDE.md',
        'your_posthog_api_key',
        'your_posthog_api_key',
        'export const KEY = "your_posthog_api_key";',
      ),
    ).toBe(true);
  });

  it('does not suppress the same key outside docs paths', () => {
    const line = 'apiKey = "ecfff8a35d82ecff7e911d57d7be8510"';
    expect(
      shouldSuppressDocContextMatch(
        'api-key-generic',
        'src/config.ts',
        'ecfff8a35d82ecff7e911d57d7be8510',
        line,
        line,
      ),
    ).toBe(false);
  });
});
