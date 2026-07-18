<?php
if ( ! defined( 'ABSPATH' ) ) exit;

function shield_get_settings() {
    $defaults = array(
        'login_slug'        => '',
        'hide_login'        => '0',
        'bot_redirect_404'  => '1',
        'auto_update'       => '1',
        'email_alerts'      => '1',
        'alert_email'       => get_option( 'admin_email' ),
        'excluded_paths'    => '',
    );
    $saved = get_option( SHIELD_OPT, array() );
    return array_merge( $defaults, $saved );
}

function shield_save_settings( $data ) {
    $current = shield_get_settings();
    update_option( SHIELD_OPT, array_merge( $current, $data ) );
}

function shield_is_licensed() {
    return Shield_License::is_valid();
}

function shield_log( $message, $level = 'info' ) {
    $logs = get_option( 'shield_scan_log', array() );
    array_unshift( $logs, array(
        'time'    => current_time( 'mysql' ),
        'level'   => $level,
        'message' => $message,
    ) );
    update_option( 'shield_scan_log', array_slice( $logs, 0, 200 ) );
}

function shield_send_alert( $subject, $body ) {
    $settings = shield_get_settings();
    if ( $settings['email_alerts'] !== '1' ) return;
    $email = sanitize_email( $settings['alert_email'] );
    if ( ! $email ) return;
    $site = get_bloginfo( 'name' );
    wp_mail( $email, "[Shield Security] [{$site}] {$subject}", $body );
}

function shield_nonce_field() {
    wp_nonce_field( 'shield_action', 'shield_nonce' );
}

function shield_verify_nonce() {
    if ( ! isset( $_POST['shield_nonce'] ) ) return false;
    return (bool) wp_verify_nonce( sanitize_key( $_POST['shield_nonce'] ), 'shield_action' );
}

function shield_admin_only() {
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );
}

/**
 * Get list of paths excluded from scanning (plugin's own dir is always excluded).
 * Returns array of normalised absolute paths.
 */
function shield_get_excluded_paths() {
    // Always exclude own plugin directory
    $excluded = array( rtrim( str_replace( '\\', '/', SHIELD_DIR ), '/' ) );

    $settings = shield_get_settings();
    $raw = trim( $settings['excluded_paths'] ?? '' );
    if ( $raw ) {
        $lines = explode( "\n", $raw );
        foreach ( $lines as $line ) {
            $line = trim( str_replace( '\\', '/', $line ) );
            if ( $line ) {
                // Allow relative paths (relative to ABSPATH)
                if ( strpos( $line, '/' ) !== 0 && strpos( $line, ':' ) === false ) {
                    $line = rtrim( str_replace( '\\', '/', ABSPATH ), '/' ) . '/' . $line;
                }
                $excluded[] = rtrim( $line, '/' );
            }
        }
    }
    return array_unique( $excluded );
}

function shield_path_is_excluded( $path ) {
    $path = rtrim( str_replace( '\\', '/', $path ), '/' );
    foreach ( shield_get_excluded_paths() as $ex ) {
        if ( $path === $ex || strpos( $path, $ex . '/' ) === 0 ) return true;
    }
    return false;
}
