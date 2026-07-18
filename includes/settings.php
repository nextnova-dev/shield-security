<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Shield_Settings {

    public static function init() {
        add_action( 'admin_init', array( __CLASS__, 'handle_post' ) );
    }

    public static function activate() {
        if ( ! get_option( SHIELD_OPT ) ) {
            update_option( SHIELD_OPT, array(
                'login_slug'       => 'site-login',
                'hide_login'       => '0',
                'bot_redirect_404' => '1',
                'auto_update'      => '1',
                'email_alerts'     => '1',
                'alert_email'      => get_option( 'admin_email' ),
                'excluded_paths'   => '',
            ) );
        }
        flush_rewrite_rules();
    }

    public static function handle_post() {
        if ( empty( $_POST['shield_action'] ) || $_POST['shield_action'] !== 'save_settings' ) return;
        shield_admin_only();
        if ( ! shield_verify_nonce() ) wp_die( 'Bad nonce' );

        $old  = shield_get_settings();
        $slug = sanitize_title( $_POST['shield_login_slug'] ?? '' );

        shield_save_settings( array(
            'login_slug'       => $slug,
            'hide_login'       => isset( $_POST['shield_hide_login'] )       ? '1' : '0',
            'bot_redirect_404' => isset( $_POST['shield_bot_redirect_404'] ) ? '1' : '0',
            'auto_update'      => isset( $_POST['shield_auto_update'] )      ? '1' : '0',
            'email_alerts'     => isset( $_POST['shield_email_alerts'] )     ? '1' : '0',
            'alert_email'      => sanitize_email( $_POST['shield_alert_email'] ?? '' ),
            'excluded_paths'   => sanitize_textarea_field( wp_unslash( $_POST['shield_excluded_paths'] ?? '' ) ),
        ) );

        if ( $slug !== $old['login_slug'] ) flush_rewrite_rules();

        wp_redirect( add_query_arg( array( 'page' => 'shield-settings', 'shield_saved' => 1 ), admin_url( 'admin.php' ) ) );
        exit;
    }
}
