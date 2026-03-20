---
name: proto-regen
description: Regenerate TypeScript protobuf types from the canonical dsm_app.proto schema
disable-model-invocation: true
---

# Proto Regeneration

Regenerate TypeScript protobuf types from the canonical proto schema. Run this after any changes to `proto/dsm_app.proto`.

## Steps

### 1. Regenerate TypeScript protobuf types

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/new_frontend && \
npm run proto:gen
```

This runs `protoc` with `protoc-gen-es` to generate `src/proto/dsm_app_pb.ts` from `../../proto/dsm_app.proto`.

### 2. Verify generated file exists and has content

```bash
wc -l /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/new_frontend/src/proto/dsm_app_pb.ts
```

The generated file should be substantial (thousands of lines). If it's empty or missing, the generation failed.

### 3. Type-check to verify compatibility

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/new_frontend && \
npm run type-check
```

This ensures the regenerated types are compatible with all existing code.

### 4. Report summary

Report:
- Whether proto:gen succeeded
- Line count of generated file
- Whether type-check passed
- Any errors encountered
