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

/**
 * File lock settings — separate class to keep things clean
 */
class Shield_File_Lock {

    public static function init() {
        add_action( 'admin_init', array( __CLASS__, 'handle_post' ) );
        // Enforce DISALLOW_FILE_MODS at runtime if enabled in DB
        // (wp-config.php is the primary source, but this is a safety net)
    }

    public static function handle_post() {
        if ( empty( $_POST['shield_lock_action'] ) ) return;
        shield_admin_only();
        if ( ! shield_verify_nonce() ) wp_die( 'Bad nonce' );

        $action = sanitize_key( $_POST['shield_lock_action'] );

        switch ( $action ) {

            case 'enable_file_mods_lock':
                $ok = shield_wpconfig_add_define( 'DISALLOW_FILE_MODS' );
                $msg = $ok ? 'lock_enabled' : 'lock_error';
                break;

            case 'disable_file_mods_lock':
                $ok = shield_wpconfig_remove_define( 'DISALLOW_FILE_MODS' );
                // Also remove file edit lock if it was set separately
                shield_wpconfig_remove_define( 'DISALLOW_FILE_EDIT' );
                $msg = $ok ? 'lock_disabled' : 'lock_error';
                break;

            case 'enable_file_edit_lock':
                $ok = shield_wpconfig_add_define( 'DISALLOW_FILE_EDIT' );
                $msg = $ok ? 'edit_lock_enabled' : 'lock_error';
                break;

            case 'disable_file_edit_lock':
                $ok = shield_wpconfig_remove_define( 'DISALLOW_FILE_EDIT' );
                $msg = $ok ? 'edit_lock_disabled' : 'lock_error';
                break;

            case 'block_uploads_php':
                $result = shield_block_uploads_php_htaccess();
                $msg    = $result['ok'] ? 'uploads_blocked' : 'lock_error';
                break;

            case 'unblock_uploads_php':
                $result = shield_unblock_uploads_php_htaccess();
                $msg    = $result['ok'] ? 'uploads_unblocked' : 'lock_error';
                break;

            case 'mark_nginx_blocked':
                update_option( 'shield_nginx_uploads_blocked', '1' );
                $msg = 'nginx_marked';
                break;

            case 'unmark_nginx_blocked':
                delete_option( 'shield_nginx_uploads_blocked' );
                $msg = 'nginx_unmarked';
                break;

            default:
                $msg = 'lock_error';
        }

        wp_redirect( add_query_arg( array( 'page' => 'shield-lockdown', 'msg' => $msg ), admin_url( 'admin.php' ) ) );
        exit;
    }
}
