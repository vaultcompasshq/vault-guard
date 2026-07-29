# Configuration

FP guard: docs commonly write placeholders in the hyphenated `your-*` form.
The underscore form (`your_api_key`) was already suppressed; the hyphen form
was not, and fired as `api-key-generic` at `high` on real repositories.

Copy `.env.example` to `.env` and fill in your own values:

```bash
ANTHROPIC_API_KEY="your-anthropic-api-key"
OPENAI_API_KEY="your-openai-api-key-here"
GROQ_API_KEY="your-groq-api-key-goes-here"
```

In JSON config the same convention applies:

```json
{
  "api_key": "your-key-goes-right-here",
  "secret": "your-signing-secret-value"
}
```

None of the values above is a credential.
