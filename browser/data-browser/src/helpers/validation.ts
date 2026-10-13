// @wc-ignore-file
import { config } from 'zod/v4/core';

// The server's CSP permits WebAssembly but forbids JavaScript compilation.
// Configure this before App imports schemas, including lazy SDK schemas.
// Firefox reports even a caught capability probe as a CSP violation.
config({ jitless: true });
