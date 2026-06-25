<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Login URL hardening — PHP 7.0 compatible
 * - Renames /wp-login.php to a custom slug
 * - Blocks direct /wp-admin access for non-logged-in users
 * - Redirects bots and unknown visitors to 404
 */
class Shield_Login_Hardening {

    private static $slug = '';

    public static function init() {
        $settings   = shield_get_settings();
        self::$slug = trim( $settings['login_slug'] );

        if ( $settings['hide_login'] !== '1' || empty( self::$slug ) ) return;

        // Register the custom login URL as a rewrite rule
        add_action( 'init',                  array( __CLASS__, 'add_rewrite_rule' ) );
        add_filter( 'login_url',             array( __CLASS__, 'filter_login_url' ), 10, 3 );
        add_filter( 'logout_url',            array( __CLASS__, 'filter_logout_url' ), 10, 2 );
        add_filter( 'lostpassword_url',      array( __CLASS__, 'filter_lostpw_url' ), 10, 2 );
        add_filter( 'network_site_url',      array( __CLASS__, 'filter_network_url' ), 10, 3 );
        add_filter( 'wp_redirect',           array( __CLASS__, 'filter_redirect' ), 10, 2 );
        add_action( 'init',                  array( __CLASS__, 'intercept_request' ), 1 );
        add_action( 'wp_loaded',             array( __CLASS__, 'block_default_login' ) );
    }

    public static function deactivate() {
        flush_rewrite_rules();
    }

    public static function add_rewrite_rule() {
        add_rewrite_rule( '^' . preg_quote( self::$slug, '/' ) . '/?$', 'index.php?shield_login=1', 'top' );
        add_rewrite_tag( '%shield_login%', '([^&]+)' );
    }

    /**
     * Intercept the custom login URL before WordPress routing
     */
    public static function intercept_request() {
        $slug = self::$slug;
        $request = trim( parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ), '/' );

        // Strip subfolder if WP is installed in a subdirectory
        $home_path = trim( parse_url( home_url(), PHP_URL_PATH ), '/' );
        if ( $home_path && strpos( $request, $home_path ) === 0 ) {
            $request = trim( substr( $request, strlen( $home_path ) ), '/' );
        }

        // Serve wp-login.php when custom slug is accessed
        if ( $request === $slug ) {
            // Allow only if coming from a valid referrer or directly
            require_once ABSPATH . 'wp-login.php';
            exit;
        }
    }

    /**
     * Block /wp-login.php direct access and /wp-admin for non-logged-in users
     */
    public static function block_default_login() {
        $request = trim( parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ), '/' );
        $home_path = trim( parse_url( home_url(), PHP_URL_PATH ), '/' );
        if ( $home_path && strpos( $request, $home_path ) === 0 ) {
            $request = trim( substr( $request, strlen( $home_path ) ), '/' );
        }

        $is_login    = ( $request === 'wp-login.php' || strpos( $request, 'wp-login.php' ) === 0 );
        $is_admin    = ( $request === 'wp-admin' || strpos( $request, 'wp-admin/' ) === 0 );
        $is_ajax     = ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || strpos( $request, 'wp-admin/admin-ajax.php' ) !== false;
        $is_cron     = ( defined( 'DOING_CRON' ) && DOING_CRON );
        $is_rest     = ( defined( 'REST_REQUEST' ) && REST_REQUEST );
        $is_loggedin = is_user_logged_in();

        // Always allow admin-ajax.php (needed for many plugins)
        if ( $is_ajax || $is_cron || $is_rest ) return;

        // Block direct wp-login.php access
        if ( $is_login ) {
            $settings = shield_get_settings();
            if ( $settings['bot_redirect_404'] === '1' ) {
                // 404 for bots, redirect for humans
                if ( self::is_bot() ) {
                    status_header( 404 );
                    nocache_headers();
                    include get_404_template();
                    exit;
                }
            }
            // Redirect to 404 for all — they should use the custom URL
            wp_redirect( home_url( '/404' ), 302 );
            exit;
        }

        // Block wp-admin for non-logged-in visitors
        if ( $is_admin && ! $is_loggedin ) {
            $settings = shield_get_settings();
            if ( $settings['bot_redirect_404'] === '1' && self::is_bot() ) {
                status_header( 404 );
                nocache_headers();
                include get_404_template();
                exit;
            }
            wp_redirect( home_url( '/' . self::$slug ), 302 );
            exit;
        }
    }

    // ── URL filters ───────────────────────────────────────────────────

    public static function filter_login_url( $url, $redirect, $force_reauth ) {
        return self::replace_login_url( $url );
    }

    public static function filter_logout_url( $url, $redirect ) {
        return self::replace_login_url( $url );
    }

    public static function filter_lostpw_url( $url, $redirect ) {
        return self::replace_login_url( $url );
    }

    public static function filter_network_url( $url, $path, $scheme ) {
        return self::replace_login_url( $url );
    }

    public static function filter_redirect( $location, $status ) {
        return self::replace_login_url( $location );
    }

    private static function replace_login_url( $url ) {
        $slug = self::$slug;
        if ( empty( $slug ) ) return $url;
        // Replace wp-login.php with the custom slug
        return str_replace( 'wp-login.php', $slug, $url );
    }

    // ── Bot detection ─────────────────────────────────────────────────

    private static function is_bot() {
        if ( empty( $_SERVER['HTTP_USER_AGENT'] ) ) return true;
        $ua   = strtolower( $_SERVER['HTTP_USER_AGENT'] );
        $bots = array(
            'bot', 'crawl', 'spider', 'slurp', 'mediapartners', 'googlebot',
            'bingbot', 'yandex', 'duckduck', 'baiduspider', 'wget', 'curl',
            'python', 'libwww', 'scrapy', 'nikto', 'nmap', 'masscan',
            'sqlmap', 'semrush', 'ahrefs', 'mj12bot', 'dotbot',
        );
        foreach ( $bots as $bot ) {
            if ( strpos( $ua, $bot ) !== false ) return true;
        }
        return false;
    }
}
