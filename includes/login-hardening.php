<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Shield_Login_Hardening {

    private static $slug = '';

    public static function init() {
        $settings   = shield_get_settings();
        self::$slug = trim( $settings['login_slug'] );
        if ( $settings['hide_login'] !== '1' || empty( self::$slug ) ) return;
        add_action( 'init',      array( __CLASS__, 'add_rewrite_rule' ) );
        add_filter( 'login_url', array( __CLASS__, 'filter_login_url' ), 10, 3 );
        add_filter( 'logout_url',        array( __CLASS__, 'filter_other_url' ), 10, 2 );
        add_filter( 'lostpassword_url',  array( __CLASS__, 'filter_other_url' ), 10, 2 );
        add_filter( 'network_site_url',  array( __CLASS__, 'filter_other_url' ), 10, 2 );
        add_filter( 'wp_redirect',       array( __CLASS__, 'filter_other_url' ), 10, 2 );
        add_action( 'init',      array( __CLASS__, 'intercept_request' ), 1 );
        add_action( 'wp_loaded', array( __CLASS__, 'block_default_login' ) );
    }

    public static function deactivate() { flush_rewrite_rules(); }

    public static function add_rewrite_rule() {
        add_rewrite_rule( '^' . preg_quote( self::$slug, '/' ) . '/?$', 'index.php?shield_login=1', 'top' );
        add_rewrite_tag( '%shield_login%', '([^&]+)' );
    }

    public static function intercept_request() {
        $request   = trim( parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ), '/' );
        $home_path = trim( parse_url( home_url(), PHP_URL_PATH ), '/' );
        if ( $home_path && strpos( $request, $home_path ) === 0 ) {
            $request = trim( substr( $request, strlen( $home_path ) ), '/' );
        }
        if ( $request === self::$slug ) {
            require_once ABSPATH . 'wp-login.php';
            exit;
        }
    }

    public static function block_default_login() {
        $request   = trim( parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ), '/' );
        $home_path = trim( parse_url( home_url(), PHP_URL_PATH ), '/' );
        if ( $home_path && strpos( $request, $home_path ) === 0 ) {
            $request = trim( substr( $request, strlen( $home_path ) ), '/' );
        }
        $is_login    = ( $request === 'wp-login.php' || strpos( $request, 'wp-login.php' ) === 0 );
        $is_admin    = ( $request === 'wp-admin'     || strpos( $request, 'wp-admin/' ) === 0 );
        $is_ajax     = strpos( $request, 'wp-admin/admin-ajax.php' ) !== false;
        $is_loggedin = is_user_logged_in();
        if ( $is_ajax ) return;
        $settings = shield_get_settings();
        if ( $is_login ) {
            if ( $settings['bot_redirect_404'] === '1' && self::is_bot() ) {
                status_header( 404 ); nocache_headers();
                include get_404_template(); exit;
            }
            wp_redirect( home_url( '/' . self::$slug ), 302 ); exit;
        }
        if ( $is_admin && ! $is_loggedin ) {
            if ( $settings['bot_redirect_404'] === '1' && self::is_bot() ) {
                status_header( 404 ); nocache_headers();
                include get_404_template(); exit;
            }
            wp_redirect( home_url( '/' . self::$slug ), 302 ); exit;
        }
    }

    public static function filter_login_url( $url, $redirect, $force_reauth ) { return self::swap( $url ); }
    public static function filter_other_url( $url, $arg2 = '' ) { return self::swap( $url ); }
    private static function swap( $url ) {
        return empty( self::$slug ) ? $url : str_replace( 'wp-login.php', self::$slug, $url );
    }
    private static function is_bot() {
        if ( empty( $_SERVER['HTTP_USER_AGENT'] ) ) return true;
        $ua   = strtolower( $_SERVER['HTTP_USER_AGENT'] );
        $bots = array( 'bot','crawl','spider','slurp','yandex','duckduck','baidu','wget','curl','python','libwww','scrapy','nikto','nmap','masscan','sqlmap','semrush','ahrefs','mj12bot','dotbot' );
        foreach ( $bots as $b ) { if ( strpos( $ua, $b ) !== false ) return true; }
        return false;
    }
}
