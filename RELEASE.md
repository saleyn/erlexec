# Publishing a Release

This project uses automated workflows to manage releases. Follow these steps to publish a new version.

## Process

1. **Update the version** in `erlexec.app.src`:
   ```elixir
   {vsn,"2.3.1"}
   ```

2. **Commit the version bump**:
   ```bash
   git add src/erlexec.app.src
   git commit -m "Bump version to 2.3.1"
   git push origin master
   ```

3. **Automatic tag creation**: The CI workflow automatically creates a git tag based on the project version when:
   - A push is made to the `master` branch
   - The version in `src/erlexec.app.src` is greater than the max existing git tag

4. **Automatic release publishing**: Once the tag is created, the release workflow automatically:
   - Creates a GitHub release
   - Publishes the package to Hex.pm (only if the tag is greater than the max existing tag)
   - Retires the prior version on Hex.pm as deprecated

## Key Features

- **Version comparison**: Tags are compared using semantic versioning, so `1.10.0` is correctly recognized as greater than `1.9.0`
- **Idempotent publishing**: The release workflow won't publish if the tag is not greater than the max existing tag, preventing accidental downgrades
- **No manual tagging needed**: The CI workflow handles tag creation automatically based on the `src/erlexec.app.src` version

## Manual Tag Creation (if needed)

If you need to manually create a tag:

```bash
git tag 0.4.0
git push origin 0.4.0
```

This will trigger the release workflow.

## Setup Requirements

The automated workflow requires proper GitHub token configuration:

### 1. Personal Access Token (PAT)

The CI workflow needs to push tags in a way that triggers the release workflow. The default `GITHUB_TOKEN` cannot trigger workflows for security reasons, so a Personal Access Token is required.

**Create and configure `RELEASE_PAT`**:

1. Go to Profile → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Give it a name like "Release Workflow Token"
4. Select the following scopes:
   - `repo` — Full control of private repositories
   - `workflow` — Update GitHub Actions workflows
5. Click "Generate token" and copy the token (you can only see it once)
6. Add it to your repository secrets:
   - Go to your repo → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `RELEASE_PAT`
   - Value: Paste the token you just created

### 2. Hex API Key

For publishing to Hex.pm, configure your API key:

1. Go to your repository → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `HEX_API_KEY`
4. Value: Your Hex.pm API key (from https://hex.pm/users/account/keys)

## Troubleshooting

- **Tag not created**: Check that the version in `src/erlexec.app.src` is greater than the max existing git tag
- **Release workflow not triggered**: Ensure a PAT with `workflow` scope is configured (default `GITHUB_TOKEN` cannot trigger workflows)
- **Release not published**: Verify the Hex API key is configured in repository secrets (`HEX_API_KEY`)
- **Version mismatch**: Ensure the version in `src/erlexec.app.src` matches the intended release version (without the `v` prefix)
