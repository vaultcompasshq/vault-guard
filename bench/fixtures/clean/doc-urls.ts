// False positive candidates: documentation URLs that look like credentials
// Generic user:pass@ in an example URL should not be flagged
const exampleUrl = "https://user:password@example.com/api";
const docsUrl = "https://docs.example.com/auth?token=<your-token>";
