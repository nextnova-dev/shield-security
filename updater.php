<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Auto-updater via GitHub Releases.
 * Hooks into WordPress update system — shows update notification in Plugins list
 * and allows one-click update from Dashboard > Updates.
 *
 * GitHub repo must have a Release with a zip asset named shield-security.zip
 * and a release tag matching the version (e.g. v1.0.1).
 */
class Shield_Updater {

    const GITHUB_API = 'https://api.github.com/repos/' . SHIELD_GITHUB_REPO . '/releases/latest';
    const CACHE_KEY  = 'shield_update_check';
    const CACHE_TTL  = 6 * HOUR_IN_SECONDS;

    public static function init() {
        add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'check_for_update' ) );
        add_filter( 'plugins_api', array( __CLASS__, 'plugin_info' ), 10, 3 );
        add_filter( 'upgrader_source_selection', array( __CLASS__, 'fix_folder_name' ), 10, 4 );
    }

    /**
     * Called by WordPress when it checks for plugin updates.
     * Injects our GitHub release data into the update transient.
     */
    public static function check_for_update( $transient ) {
        if ( empty( $transient->checked ) ) return $transient;

        $settings = shield_get_settings();
        if ( $settings['auto_update'] !== '1' && ! shield_is_licensed() ) return $transient;

        $release = self::get_latest_release();
        if ( ! $release ) return $transient;

        $latest = ltrim( $release['tag_name'], 'v' );

        if ( version_compare( $latest, SHIELD_VERSION, '>' ) ) {
            $plugin_slug = plugin_basename( SHIELD_FILE );
            $transient->response[ $plugin_slug ] = (object) array(
                'slug'        => SHIELD_SLUG,
                'plugin'      => $plugin_slug,
                'new_version' => $latest,
                'url'         => 'https://github.com/' . SHIELD_GITHUB_REPO,
                'package'     => self::get_zip_url( $release ),
                'icons'       => array(),
                'banners'     => array(),
                'tested'      => '6.7',
                'requires_php'=> '7.0',
            );
        }

        return $transient;
    }

    /**
     * Provides plugin info for the "View Details" popup in wp-admin.
     */
    public static function plugin_info( $result, $action, $args ) {
        if ( $action !== 'plugin_information' ) return $result;
        if ( ! isset( $args->slug ) || $args->slug !== SHIELD_SLUG ) return $result;

        $release = self::get_latest_release();
        if ( ! $release ) return $result;

        $latest = ltrim( $release['tag_name'], 'v' );

        return (object) array(
            'name'          => 'Shield Security',
            'slug'          => SHIELD_SLUG,
            'version'       => $latest,
            'author'        => '<a href="https://nextnovatechnologies.com">Next Nova Technologies</a>',
            'homepage'      => 'https://github.com/' . SHIELD_GITHUB_REPO,
            'requires'      => '5.0',
            'tested'        => '6.7',
            'requires_php'  => '7.0',
            'sections'      => array(
                'description' => '<p>Professional WordPress security — malware cleanup, deep scanner, login hardening.</p>',
                'changelog'   => nl2br( esc_html( $release['body'] ?? 'See GitHub for full changelog.' ) ),
            ),
            'download_link' => self::get_zip_url( $release ),
            'last_updated'  => $release['published_at'] ?? '',
        );
    }

    /**
     * GitHub zips extract as owner-repo-hash/ — rename to plugin slug folder.
     */
    public static function fix_folder_name( $source, $remote_source, $upgrader, $hook_extra ) {
        if ( ! isset( $hook_extra['plugin'] ) ) return $source;
        if ( strpos( $hook_extra['plugin'], SHIELD_SLUG ) === false ) return $source;

        $corrected = trailingslashit( $remote_source ) . SHIELD_SLUG . '/';
        if ( $source !== $corrected ) {
            $wp_filesystem = self::get_fs();
            if ( $wp_filesystem && $wp_filesystem->move( $source, $corrected ) ) {
                return $corrected;
            }
        }
        return $source;
    }

    /**
     * Fetches latest release info from GitHub API (cached).
     */
    public static function get_latest_release() {
        $cached = get_transient( self::CACHE_KEY );
        if ( $cached !== false ) return $cached ? $cached : null;

        $response = wp_remote_get( self::GITHUB_API, array(
            'timeout' => 10,
            'headers' => array(
                'Accept'     => 'application/vnd.github.v3+json',
                'User-Agent' => 'Shield-Security-WP/' . SHIELD_VERSION,
            ),
        ) );

        if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
            set_transient( self::CACHE_KEY, false, HOUR_IN_SECONDS );
            return null;
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $data['tag_name'] ) ) {
            set_transient( self::CACHE_KEY, false, HOUR_IN_SECONDS );
            return null;
        }

        set_transient( self::CACHE_KEY, $data, self::CACHE_TTL );
        return $data;
    }

    /**
     * Extracts the zip download URL from a release.
     * Looks for an asset named shield-security.zip first, falls back to zipball.
     */
    private static function get_zip_url( $release ) {
        if ( ! empty( $release['assets'] ) ) {
            foreach ( $release['assets'] as $asset ) {
                if ( isset( $asset['name'] ) && $asset['name'] === 'shield-security.zip' ) {
                    return $asset['browser_download_url'];
                }
            }
        }
        // Fallback to GitHub's auto-generated zipball
        return $release['zipball_url'] ?? '';
    }

    private static function get_fs() {
        global $wp_filesystem;
        if ( ! $wp_filesystem ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }
        return $wp_filesystem;
    }
}
