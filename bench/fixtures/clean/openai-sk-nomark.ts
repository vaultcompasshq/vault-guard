// False-positive guard: sk- prefixed identifiers WITHOUT the T3BlbkFJ watermark
// must NOT be flagged. Config keys, short identifiers, and benign values that
// happen to start with sk- are common in codebases.

const config = {
  skuPrefix: 'sk-product-category-abc',
  socketKey: 'sk-socket-connection-id-12345',
  shortKey: 'sk-ab12cd34',
};

// A sk-proj- prefix with only short alphanumerics and no watermark is not a key
const fakeProjectKey = 'sk-proj-' + 'a'.repeat(30);

export { config, fakeProjectKey };
