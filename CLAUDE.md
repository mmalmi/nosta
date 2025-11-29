# Nosta Development Guidelines

## Test-Driven Development

Write tests for new functionality:

- **Before implementation**: Write failing tests that define expected behavior
- **During implementation**: Run tests frequently (`cargo test`)
- **After implementation**: Ensure all tests pass before committing
- **Test coverage**: Aim for tests on all public APIs
- **Integration tests**: Test actual file uploads, retrieval, and edge cases

**Testing workflow**:
1. Write test case for new feature
2. Run `cargo test` - should fail
3. Implement feature
4. Run `cargo test` - should pass
5. Refactor if needed while keeping tests green

## Rust Code Organization

Keep Rust source files maintainable:

- **Target: ~500 lines** per file - sweet spot for readability
- **Hard limit: 1000 lines** - files exceeding this MUST be split
- **Check before writing**: If adding code would push file over 1000 lines, split first
- **Splitting strategy**:
  - Extract logical modules to separate files
  - Move related functions/structs to submodules
  - Create `module/mod.rs` with multiple subfiles
  - Keep public API in parent module, implementation in submodules

**When to split**:
- File approaching 800+ lines - proactively refactor
- Natural boundaries: separate concerns, feature groups, or type families
- Example: `server.rs` → `server/mod.rs`, `server/routes.rs`, `server/handlers.rs`, `server/mime.rs`

**Current file status**:
- `src/storage.rs` - Check line count regularly
- `src/server.rs` - Check line count regularly
- `src/main.rs` - CLI only, should stay small
- `src/lib.rs` - Re-exports only
