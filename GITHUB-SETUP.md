# Shield Security — GitHub Releases Setup

## How auto-updates work

1. Push your code to GitHub at: `https://github.com/nextnova-dev/shield-security`
2. When releasing a new version:
   - Update `SHIELD_VERSION` in `shield-security.php`
   - Build a zip of the plugin folder named `shield-security.zip`
   - Go to GitHub → Releases → Draft a new release
   - Tag: `v1.0.1` (must match the version number)
   - Attach `shield-security.zip` as a release asset
   - Publish the release
3. WordPress sites with the plugin installed will see an update notification within 6 hours (cached)

## GitHub repo requirements

- Repo must be PUBLIC (free) OR you use a GitHub token for private repos
- Release tag format: `v1.0.1` (with the `v` prefix)
- Zip asset name must be exactly: `shield-security.zip`
- The zip must extract to a folder named `shield-security/`

## License server setup

1. Upload `shield-license-server/validate.php` to any PHP host
2. Update `Shield_License::VALIDATE_URL` in `includes/license.php`
3. Add your license keys to the `$licenses` array in `validate.php`
4. For production: replace the flat-file storage with a MySQL table

## Selling licenses

Recommended platforms (all free to start):
- **Lemon Squeezy** — generates license keys automatically, webhook delivers to your server
- **Gumroad** — similar, simpler API
- **WooCommerce + WC Software Add-On** — if you already have a WP site

For Lemon Squeezy: receive webhook on purchase → save key+email to DB → validate.php queries that DB.
