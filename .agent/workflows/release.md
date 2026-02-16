---
description: how to release the terraform provider
---

Follow these steps to release a new version of the provider to the Terraform Registry.

### 1. Prerequisites (One-time setup)

#### Generating a GPG Key
If you don't have a GPG key for signing:
1. Run `gpg --full-generate-key` (Select RSA/RSA, 4096 bits).
2. Find your Key ID: `gpg --list-secret-keys --keyid-format=LONG`.
3. Export Private Key for GitHub Secrets: `gpg --armor --export-secret-keys <ID>`.
4. Export Public Key for Terraform Registry: `gpg --armor --export <ID>`.

#### Configuration
1. **GitHub Secrets**: Add `GPG_PRIVATE_KEY` (private key) and `PASSPHRASE` (if any).
2. **Registry**: Upload the Public Key to [Terraform Registry GPG Keys](https://registry.terraform.io/settings/gpg-keys).

### 2. Generate Documentation

Before releasing, ensure the documentation is up to date:

```bash
make generate
```

### 3. Commit and Tag

Tagging a version will automatically trigger the GitHub Actions release workflow.

1. Ensure all changes are committed:
   ```bash
   git add .
   git commit -m "Prepare for release vX.Y.Z"
   ```

2. Create and push the tag:
   ```bash
   git tag v0.1.0  # Use the appropriate version
   git push origin v0.1.0
   ```

### 4. Verify

1. Check the **Actions** tab in your GitHub repository to ensure the "Release" workflow completes successfully.
2. Verify the new version appearing on the [Terraform Registry](https://registry.terraform.io/).
