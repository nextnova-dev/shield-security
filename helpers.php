<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Shared utility functions — PHP 7.0 compatible
 */

function shield_get_settings() {
    $defaults = array(
        'login_slug'        => '',
        'hide_login'        => '0',
        'bot_redirect_404'  => '1',
        'auto_update'       => '1',
        'scan_on_save'      => '0',
        'email_alerts'      => '1',
        'alert_email'       => get_option( 'admin_email' ),
    );
    $saved = get_option( SHIELD_OPT, array() );
    return array_merge( $defaults, $saved );
}

function shield_save_settings( $data ) {
    $current = shield_get_settings();
    $merged  = array_merge( $current, $data );
    update_option( SHIELD_OPT, $merged );
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
    // Keep last 200 log entries
    $logs = array_slice( $logs, 0, 200 );
    update_option( 'shield_scan_log', $logs );
}

function shield_send_alert( $subject, $body ) {
    $settings = shield_get_settings();
    if ( $settings['email_alerts'] !== '1' ) return;
    $email = sanitize_email( $settings['alert_email'] );
    if ( ! $email ) return;
    $site  = get_bloginfo( 'name' );
    wp_mail( $email, "[Shield Security] [{$site}] {$subject}", $body );
}

function shield_nonce_field() {
    wp_nonce_field( 'shield_action', 'shield_nonce' );
}

function shield_verify_nonce() {
    if ( ! isset( $_POST['shield_nonce'] ) ) return false;
    return wp_verify_nonce( sanitize_key( $_POST['shield_nonce'] ), 'shield_action' );
}

function shield_admin_only() {
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );
}
