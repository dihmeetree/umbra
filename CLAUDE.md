# Claude Development Guidelines

## Compilation and Testing Requirements

**IMPORTANT**: Before marking any development task as complete, you MUST:

1. **Verify compilation** by running:

   ```bash
   go build ./...
   ```

2. **Run all tests** and ensure they pass:

   ```bash
   go test ./... -race -v
   ```

3. **Run go vet** to ensure code quality standards:

   ```bash
   go vet ./...
   ```

4. **Run staticcheck** for additional linting (if available):

   ```bash
   staticcheck ./...
   ```

5. **Format code** to ensure consistent formatting:

   ```bash
   gofmt -w .
   ```

6. If you're working on multiple todos, verify compilation, tests, go vet, staticcheck, and formatting after each significant change or todo completion.

7. If compilation fails, tests break, go vet warnings occur, staticcheck issues arise, or formatting is incorrect, fix the issues before proceeding to the next task.

8. Never mark a todo as "completed" without verifying that the code compiles, all tests pass (including race detector), go vet passes without warnings, staticcheck passes (if available), and code is properly formatted.

## Development Best Practices

- Always verify that your changes don't break existing functionality
- Run tests incrementally when making multiple changes
- Use `go build ./...` for quick compilation verification during development
- Use `go test ./... -race -v` for full test suite verification before completing tasks (includes race detector)
- Use `go vet ./...` to catch common mistakes and maintain code quality
- Use `staticcheck ./...` for advanced static analysis (if available)
- Use `gofmt -w .` to ensure consistent code formatting before committing
- Run `go mod tidy` to keep dependencies clean and up-to-date

## Code Quality Standards

**NO SHORTCUTS**: All code must be production-ready and properly implemented.

1. **No Fallback to Simpler Solutions**: When facing implementation challenges, solve them properly rather than reverting to simpler, less optimal approaches.

2. **Maximum Performance**: Write code for optimal performance. This includes:

   - Using efficient algorithms and data structures
   - Minimizing allocations and copies
   - Leveraging concurrency where appropriate
   - Avoiding unnecessary iterations

3. **Security First**: All code must be written with security in mind:

   - Proper input validation
   - Protection against timing attacks
   - Secure cryptographic practices

4. **Documentation and Comments**: All code must be properly documented:

   - Every exported function, type, constant, and variable must have comprehensive documentation comments
   - Complex algorithms or business logic must be explained with comments
   - Use Go doc comments (comments directly preceding declarations) for exported APIs
   - Follow Go documentation conventions: comments should be complete sentences starting with the name of the thing being described
   - Use regular comments (`//`) to explain non-obvious implementation details
   - Comments should explain **why** something is done, not just **what** is done
   - Keep comments up-to-date when code changes
   - Package comments should appear in a doc.go file or before the package declaration

5. **No Placeholders**: Never use placeholder implementations or comments like:

   - "In a production system..."
   - "TODO: implement properly"
   - "This is a simplified version..."
   - Mock implementations that don't actually work

6. **Complete Solutions**: Every implementation must be:
   - Fully functional
   - Properly tested
   - Ready for production use
   - Maintainable and well-structured

## Code Addition Guidelines

**CRITICAL**: Never add unused code to the codebase. Follow these strict guidelines:

### **Prohibited Practices:**

1. **No Unused Functions**: Never create functions, methods, or constants that are not actively used in the codebase
2. **No Dead Code**: Do not leave commented-out code, unused imports, or unreachable code paths
3. **No "Future" Features**: Do not add functionality "for future use" unless it's immediately integrated and tested
4. **No Orphaned Utilities**: Every utility function must have at least one active caller in the current codebase

### **Required Practices:**

1. **Integration Mandatory**: When adding new functionality:

   - **MUST** be properly integrated into existing code flows
   - **MUST** have active callers or be part of public APIs that are used
   - **MUST** be covered by tests that demonstrate actual usage

2. **Verification Steps**: Before adding any new code:

   - Identify exactly where and how it will be used
   - Implement the caller/integration point first
   - Verify the new code is actually exercised by existing functionality
   - Run `go build ./...` and `go vet ./...` to ensure no "unused" or "unreachable" warnings for your additions

3. **Maintenance Integration**: New maintenance or cleanup functions:
   - **MUST** be called from appropriate places (startup, periodic tasks, shutdown, etc.)
   - **MUST** be integrated into existing maintenance loops where applicable
   - **MUST** be covered by integration tests or have clear usage patterns

### **Examples of Proper Integration:**

✅ **GOOD**: Adding `PerformMaintenance()` method AND integrating it into `NetworkManager.MaintainPeers()`
✅ **GOOD**: Creating helper functions that are immediately used by existing exported methods
✅ **GOOD**: Adding constants that are actively referenced by current algorithms

❌ **BAD**: Creating utility functions "that might be useful later"
❌ **BAD**: Adding constants that are not referenced anywhere
❌ **BAD**: Implementing methods that have no current callers
❌ **BAD**: Creating "framework" code without immediate concrete usage

### **Code Review Checklist:**

Before completing any development task, verify:

- [ ] No compiler warnings about unused code
- [ ] All new functions/methods have active callers
- [ ] All new constants are actually used
- [ ] Integration points are properly tested
- [ ] Documentation reflects actual usage, not theoretical usage

## Git Commit and Push Guidelines

**IMPORTANT**: Follow these guidelines for all commits to maintain high-quality version control.

### **Pre-Commit Requirements**

Before creating any commit, you MUST:

1. **Format all code** before adding to git:

   ```bash
   gofmt -w .
   ```

   **CRITICAL**: Always run `gofmt -w .` BEFORE running `git add`. This ensures all code follows consistent formatting standards and prevents formatting-related commit conflicts.

2. **Run the full validation suite** in parallel:

   ```bash
   go build ./... && go vet ./... && go test ./... -race
   ```

   Optionally, also run staticcheck if available:

   ```bash
   staticcheck ./...
   ```

3. **Verify all changes are intentional**:

   - Review `git status` to see all modified files
   - Review `git diff` to understand all changes being committed
   - Ensure no temporary files, debug code, or sensitive information is included

4. **Check recent commit history** for consistency:
   ```bash
   git log --oneline -5
   ```

### **Commit Message Standards**

#### **Required Format**

```
<type>: <concise description>

## <section headers as needed>

### **<subsection headers for details>**
- ✅ Bullet points for completed features
- 🚀 Performance improvements
- 🔧 Configuration changes
- 📝 Documentation updates
- 🐛 Bug fixes

<mandatory footer>
🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

#### **Commit Types**

- **feat**: New features or major enhancements
- **fix**: Bug fixes and corrections
- **perf**: Performance optimizations
- **refactor**: Code restructuring without functional changes
- **docs**: Documentation updates
- **config**: Configuration file changes
- **test**: Test additions or modifications
- **chore**: Maintenance tasks and minor updates

#### **Writing Quality Commit Messages**

**DO:**

- Start with a clear, imperative verb (Add, Fix, Update, Optimize, etc.)
- Summarize the "why" and impact, not just the "what"
- Use structured sections (## and ###) for complex changes
- Include specific technical details for significant changes
- Use emojis consistently for visual scanning
- Group related changes logically
- Mention breaking changes explicitly

**DON'T:**

- Use vague descriptions like "update code" or "fix issues"
- Include temporary or debugging information
- Write overly long single-line descriptions
- Mix unrelated changes in one commit
- Commit sensitive information (keys, passwords, etc.)

#### **Example Commit Messages**

**Simple Fix:**

```
fix: Resolve connection timeout in health check HTTP requests

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

**Feature Addition:**

```
feat: Add Redis-based session storage with connection pooling

## New Features
- ✅ Redis session backend implementation
- 🔧 Configurable connection pool settings
- 📝 Session TTL and cleanup policies

## Configuration Changes
- Add redis_url and pool_size to config.yaml
- Update config.example.yaml with Redis examples

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

**Major Optimization:**

```
perf: Optimize load balancer with concurrent-safe data structures and circuit breakers

## Performance Improvements
- 🚀 Replace map with sync.Map for 40% faster upstream selection
- 🚀 Implement lock-free circuit breaker pattern using atomic operations
- 🚀 Add consistent hashing algorithm with 150 virtual nodes per server

## Memory Optimizations
- Reduce RequestContext allocation by 60% using pointer fields for optional data
- Optimize weighted round-robin from O(weights × servers) to O(servers)

## Breaking Changes
- RequestContext.CustomData is now *map[string]interface{} (pointer for optional data)
- LoadBalancingAlgorithm type adds ConsistentHash constant

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

### **Push Guidelines**

#### **Before Pushing**

1. **Verify commit integrity**:

   ```bash
   git status  # Should show clean working tree
   git log --oneline -1  # Verify commit message format
   ```

2. **Ensure branch is up to date**:

   ```bash
   git fetch origin
   git status  # Check if behind origin
   ```

3. **Final validation**: Re-run tests if there were any remote changes merged

#### **Push Process**

1. **Standard push**:

   ```bash
   git push origin main
   ```

2. **Force push only when necessary** (and document why):
   ```bash
   git push --force-with-lease origin main
   ```

#### **Post-Push Verification**

1. **Confirm push succeeded**: Check GitHub web interface
2. **Verify CI/CD pipelines** (if configured)
3. **Monitor for any immediate issues**

### **Multi-File Commit Strategy**

When committing changes across multiple files:

1. **Group related changes**: Commit related functionality together
2. **Separate concerns**: Don't mix features, fixes, and refactoring
3. **Use staged commits** for complex changes:
   ```bash
   git add specific_files
   git commit -m "feat: specific feature"
   git add other_files
   git commit -m "refactor: related cleanup"
   ```

### **Emergency Procedures**

#### **If Push Fails**

1. Fetch latest changes: `git fetch origin`
2. Rebase or merge as appropriate: `git rebase origin/main`
3. Resolve conflicts if any
4. Re-run validation suite
5. Push again

#### **If Commit Contains Errors**

1. **Before push**: `git commit --amend` to fix
2. **After push**: Create follow-up commit with fix

#### **If Sensitive Data Committed**

1. **NEVER push** if not already pushed
2. **If already pushed**: Immediately contact team lead
3. Reset branch and recommit without sensitive data

### **Commit Quality Checklist**

Before every commit, verify:

- [ ] **Code is formatted**: `gofmt -w .` run before `git add`
- [ ] All code compiles without warnings: `go build ./...`
- [ ] All tests pass with race detector: `go test ./... -race`
- [ ] Go vet passes: `go vet ./...`
- [ ] Staticcheck passes (if available): `staticcheck ./...`
- [ ] Dependencies are tidy: `go mod tidy`
- [ ] Commit message follows format standards
- [ ] No sensitive information included
- [ ] Changes are logically grouped
- [ ] Breaking changes are documented
- [ ] Required footer is present
