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

// ── File Modification Lock ────────────────────────────────────────────

/**
 * Read wp-config.php safely
 */
function shield_read_wpconfig() {
    $path = ABSPATH . 'wp-config.php';
    if ( ! file_exists( $path ) ) return false;
    return @file_get_contents( $path );
}

/**
 * Write wp-config.php safely — makes a backup first
 */
function shield_write_wpconfig( $content ) {
    $path   = ABSPATH . 'wp-config.php';
    $backup = ABSPATH . 'wp-config.shield-backup.php';
    // Backup before writing
    @copy( $path, $backup );
    $result = @file_put_contents( $path, $content );
    return $result !== false;
}

/**
 * Check if a define is currently set in wp-config.php by Shield
 */
function shield_wpconfig_has_define( $constant ) {
    $content = shield_read_wpconfig();
    if ( ! $content ) return false;
    // Look for our marker comment
    return strpos( $content, '/* Shield Security: ' . $constant . ' */' ) !== false;
}

/**
 * Add a define to wp-config.php (with Shield marker so we can remove it later)
 * Inserts after the opening <?php tag
 */
function shield_wpconfig_add_define( $constant, $value = 'true' ) {
    if ( shield_wpconfig_has_define( $constant ) ) return true; // already there

    $content = shield_read_wpconfig();
    if ( ! $content ) return false;

    $line = "\ndefine( '" . $constant . "', " . $value . " ); /* Shield Security: " . $constant . " */\n";

    // Insert right after <?php
    $pos = strpos( $content, '<?php' );
    if ( $pos === false ) return false;
    $insert_at = $pos + 5; // after '<?php'
    $content   = substr( $content, 0, $insert_at ) . $line . substr( $content, $insert_at );

    return shield_write_wpconfig( $content );
}

/**
 * Remove a Shield-managed define from wp-config.php
 */
function shield_wpconfig_remove_define( $constant ) {
    $content = shield_read_wpconfig();
    if ( ! $content ) return false;

    // Remove the exact line we added (marker comment included)
    $pattern = '/\r?\ndefine\s*\(\s*\'' . preg_quote( $constant, '/' ) . '\'\s*,\s*[^;]+\);\s*\/\* Shield Security: ' . preg_quote( $constant, '/' ) . ' \*\/\r?\n/';
    $new_content = preg_replace( $pattern, "\n", $content );

    if ( $new_content === $content ) return true; // wasn't there, that's fine
    return shield_write_wpconfig( $new_content );
}

/**
 * Get the current lock status from wp-config.php
 */
function shield_get_lock_status() {
    return array(
        'file_mods' => shield_wpconfig_has_define( 'DISALLOW_FILE_MODS' ),
        'file_edit' => shield_wpconfig_has_define( 'DISALLOW_FILE_EDIT' ),
        'wpconfig_writable' => is_writable( ABSPATH . 'wp-config.php' ),
    );
}
