<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Shield_License {

    const VALIDATE_URL = 'https://nextnova-lic.com/api/shield/validate';
    const CACHE_KEY    = 'shield_lic_status';
    const CACHE_TTL    = 43200; // 12 hours

    public static function init() {
        add_action( 'admin_init', array( __CLASS__, 'handle_post' ) );
    }

    public static function is_valid() {
        if ( defined( 'SHIELD_DEV_MODE' ) && SHIELD_DEV_MODE ) return true;
        $cached = get_transient( self::CACHE_KEY );
        if ( $cached !== false ) return $cached === 'valid';
        $data = get_option( SHIELD_LIC_OPT, array() );
        if ( empty( $data['key'] ) || empty( $data['status'] ) || $data['status'] !== 'active' ) return false;
        return self::remote_validate( $data['key'] );
    }

    public static function get_key() {
        $data = get_option( SHIELD_LIC_OPT, array() );
        return isset( $data['key'] ) ? $data['key'] : '';
    }

    public static function get_status_label() {
        $data = get_option( SHIELD_LIC_OPT, array() );
        if ( empty( $data['key'] ) )
            return array( 'label' => 'Not Activated', 'color' => '#888' );
        if ( ! empty( $data['status'] ) && $data['status'] === 'active' )
            return array( 'label' => 'Active ✔', 'color' => '#155724' );
        if ( ! empty( $data['status'] ) && $data['status'] === 'expired' )
            return array( 'label' => 'Expired', 'color' => '#856404' );
        return array( 'label' => 'Invalid', 'color' => '#c0392b' );
    }

    public static function handle_post() {
        if ( empty( $_POST['shield_license_action'] ) ) return;
        shield_admin_only();
        if ( ! shield_verify_nonce() ) wp_die( 'Bad nonce' );

        $action = sanitize_key( $_POST['shield_license_action'] );
        $key    = sanitize_text_field( $_POST['shield_license_key'] ?? '' );

        if ( $action === 'activate' && $key ) {
            if ( self::remote_validate( $key, true ) ) {
                update_option( SHIELD_LIC_OPT, array( 'key' => $key, 'status' => 'active', 'domain' => home_url() ) );
                set_transient( self::CACHE_KEY, 'valid', self::CACHE_TTL );
                wp_redirect( add_query_arg( array( 'page' => 'shield-license', 'lic_msg' => 'activated' ), admin_url( 'admin.php' ) ) );
            } else {
                wp_redirect( add_query_arg( array( 'page' => 'shield-license', 'lic_msg' => 'invalid' ), admin_url( 'admin.php' ) ) );
            }
            exit;
        }

        if ( $action === 'deactivate' ) {
            $data = get_option( SHIELD_LIC_OPT, array() );
            if ( ! empty( $data['key'] ) ) self::remote_deactivate( $data['key'] );
            delete_option( SHIELD_LIC_OPT );
            delete_transient( self::CACHE_KEY );
            wp_redirect( add_query_arg( array( 'page' => 'shield-license', 'lic_msg' => 'deactivated' ), admin_url( 'admin.php' ) ) );
            exit;
        }
    }

    private static function remote_validate( $key, $activate = false ) {
        $response = wp_remote_post( self::VALIDATE_URL, array(
            'timeout' => 10,
            'body'    => array(
                'license_key' => $key,
                'domain'      => home_url(),
                'action'      => $activate ? 'activate' : 'check',
                'plugin'      => SHIELD_SLUG,
                'version'     => SHIELD_VERSION,
            ),
        ) );
        if ( is_wp_error( $response ) ) {
            set_transient( self::CACHE_KEY, 'valid', 3600 );
            return true;
        }
        $body  = json_decode( wp_remote_retrieve_body( $response ), true );
        $valid = ! empty( $body['valid'] );
        set_transient( self::CACHE_KEY, $valid ? 'valid' : 'invalid', self::CACHE_TTL );
        return $valid;
    }

    private static function remote_deactivate( $key ) {
        wp_remote_post( self::VALIDATE_URL, array(
            'timeout' => 5,
            'body'    => array(
                'license_key' => $key,
                'domain'      => home_url(),
                'action'      => 'deactivate',
                'plugin'      => SHIELD_SLUG,
            ),
        ) );
    }
}
