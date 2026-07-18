<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Shield_Updater {

    const GITHUB_API = 'https://api.github.com/repos/' . SHIELD_GITHUB_REPO . '/releases/latest';
    const CACHE_KEY  = 'shield_update_check';
    const CACHE_TTL  = 21600; // 6 hours

    public static function init() {
        add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'check_for_update' ) );
        add_filter( 'plugins_api', array( __CLASS__, 'plugin_info' ), 10, 3 );
        add_filter( 'upgrader_source_selection', array( __CLASS__, 'fix_folder_name' ), 10, 4 );
    }

    public static function check_for_update( $transient ) {
        if ( empty( $transient->checked ) ) return $transient;
        $release = self::get_latest_release();
        if ( ! $release ) return $transient;
        $latest = ltrim( $release['tag_name'], 'v' );
        if ( version_compare( $latest, SHIELD_VERSION, '>' ) ) {
            $slug = plugin_basename( SHIELD_FILE );
            $transient->response[ $slug ] = (object) array(
                'slug'         => SHIELD_SLUG,
                'plugin'       => $slug,
                'new_version'  => $latest,
                'url'          => 'https://github.com/' . SHIELD_GITHUB_REPO,
                'package'      => self::get_zip_url( $release ),
                'tested'       => '6.7',
                'requires_php' => '7.0',
            );
        }
        return $transient;
    }

    public static function plugin_info( $result, $action, $args ) {
        if ( $action !== 'plugin_information' ) return $result;
        if ( empty( $args->slug ) || $args->slug !== SHIELD_SLUG ) return $result;
        $release = self::get_latest_release();
        if ( ! $release ) return $result;
        return (object) array(
            'name'         => 'Shield Security',
            'slug'         => SHIELD_SLUG,
            'version'      => ltrim( $release['tag_name'], 'v' ),
            'author'       => '<a href="https://nextnovatechnologies.com">Next Nova Technologies</a>',
            'requires'     => '5.0',
            'tested'       => '6.7',
            'requires_php' => '7.0',
            'sections'     => array(
                'description' => '<p>Professional WordPress security scanner, login hardening, and auto-updates.</p>',
                'changelog'   => nl2br( esc_html( $release['body'] ?? '' ) ),
            ),
            'download_link' => self::get_zip_url( $release ),
            'last_updated'  => $release['published_at'] ?? '',
        );
    }

    public static function fix_folder_name( $source, $remote_source, $upgrader, $hook_extra ) {
        if ( empty( $hook_extra['plugin'] ) || strpos( $hook_extra['plugin'], SHIELD_SLUG ) === false ) return $source;
        $corrected = trailingslashit( $remote_source ) . SHIELD_SLUG . '/';
        if ( $source !== $corrected ) {
            global $wp_filesystem;
            if ( ! $wp_filesystem ) { require_once ABSPATH . 'wp-admin/includes/file.php'; WP_Filesystem(); }
            if ( $wp_filesystem && $wp_filesystem->move( $source, $corrected ) ) return $corrected;
        }
        return $source;
    }

    public static function get_latest_release() {
        $cached = get_transient( self::CACHE_KEY );
        if ( $cached !== false ) return $cached ? $cached : null;
        $response = wp_remote_get( self::GITHUB_API, array(
            'timeout' => 10,
            'headers' => array( 'Accept' => 'application/vnd.github.v3+json', 'User-Agent' => 'Shield-Security/' . SHIELD_VERSION ),
        ) );
        if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
            set_transient( self::CACHE_KEY, false, 3600 );
            return null;
        }
        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $data['tag_name'] ) ) { set_transient( self::CACHE_KEY, false, 3600 ); return null; }
        set_transient( self::CACHE_KEY, $data, self::CACHE_TTL );
        return $data;
    }

    private static function get_zip_url( $release ) {
        if ( ! empty( $release['assets'] ) ) {
            foreach ( $release['assets'] as $asset ) {
                if ( isset( $asset['name'] ) && $asset['name'] === 'shield-security.zip' ) return $asset['browser_download_url'];
            }
        }
        return isset( $release['zipball_url'] ) ? $release['zipball_url'] : '';
    }
}
