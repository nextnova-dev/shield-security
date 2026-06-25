<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * One-click cleanup engine — PHP 7.0 compatible
 * Removes threats identified by the scanner
 */
class Shield_Cleanup {

    /**
     * Remove a single threat by its data array (returned by scanner).
     * Returns array( 'ok' => bool, 'message' => string )
     */
    public static function remove_threat( $threat ) {
        $type = isset( $threat['type'] ) ? $threat['type'] : '';

        switch ( $type ) {
            case 'signature':
            case 'heuristic':
            case 'credential_log':
                return self::remove_file( $threat );

            case 'database':
                return self::remove_db_option( $threat );

            case 'cron':
                return self::remove_cron( $threat );

            case 'user':
                return self::remove_user( $threat );

            default:
                return array( 'ok' => false, 'message' => 'Unknown threat type: ' . esc_html( $type ) );
        }
    }

    /**
     * Remove all threats from the last scan result
     */
    public static function remove_all( $threats ) {
        $log = array();
        foreach ( $threats as $threat ) {
            $result  = self::remove_threat( $threat );
            $log[]   = $result;
            $level   = $result['ok'] ? 'info' : 'warn';
            shield_log( $result['message'], $level );
        }
        return $log;
    }

    // ── File removal ──────────────────────────────────────────────────

    private static function remove_file( $threat ) {
        if ( empty( $threat['file'] ) ) {
            return array( 'ok' => false, 'message' => 'No file path in threat data.' );
        }
        $path = $threat['file'];
        if ( ! file_exists( $path ) ) {
            return array( 'ok' => true, 'message' => 'Already gone: ' . esc_html( $threat['location'] ) );
        }

        // For drop-in files that may have legitimate content, strip the injected block
        $dropin_names = array( 'advanced-cache.php', 'db.php', 'object-cache.php' );
        if ( in_array( basename( $path ), $dropin_names, true ) ) {
            return self::strip_dropin_injection( $path, $threat );
        }

        if ( @unlink( $path ) ) {
            return array( 'ok' => true, 'message' => 'Deleted file: ' . esc_html( $threat['location'] ) );
        }
        return array( 'ok' => false, 'message' => 'Could not delete (check permissions): ' . esc_html( $threat['location'] ) );
    }

    private static function strip_dropin_injection( $path, $threat ) {
        $content = @file_get_contents( $path );
        if ( ! $content ) {
            return array( 'ok' => false, 'message' => 'Cannot read drop-in: ' . esc_html( $threat['location'] ) );
        }

        // Known signatures used to mark injection boundaries
        $sigs = array( '_ac_23da9d25', '_ac_07d0b218', '_wpc_375586e3', '_ac_ce79ae25', '_wpc_0b8206e3' );
        $sig_found = '';
        foreach ( $sigs as $s ) {
            if ( strpos( $content, $s ) !== false ) { $sig_found = $s; break; }
        }

        // Fully malware-generated drop-in
        $is_only = strpos( $content, 'WordPress Advanced Cache Plugin' ) !== false
                || strpos( $content, 'WordPress Database Abstraction' ) !== false
                || strpos( $content, 'WordPress Object Cache' ) !== false;

        if ( $is_only ) {
            if ( @unlink( $path ) ) {
                return array( 'ok' => true, 'message' => 'Deleted malware drop-in: ' . esc_html( $threat['location'] ) );
            }
            return array( 'ok' => false, 'message' => 'Cannot delete drop-in: ' . esc_html( $threat['location'] ) );
        }

        if ( $sig_found ) {
            $clean = rtrim( substr( $content, 0, strpos( $content, $sig_found ) ) );
            if ( @file_put_contents( $path, $clean ) ) {
                return array( 'ok' => true, 'message' => 'Stripped injection from drop-in: ' . esc_html( $threat['location'] ) );
            }
            return array( 'ok' => false, 'message' => 'Cannot write cleaned drop-in: ' . esc_html( $threat['location'] ) );
        }

        return array( 'ok' => false, 'message' => 'Could not isolate injection in: ' . esc_html( $threat['location'] ) . ' — review manually.' );
    }

    // ── Database removal ──────────────────────────────────────────────

    private static function remove_db_option( $threat ) {
        global $wpdb;

        if ( ! empty( $threat['option_name'] ) ) {
            delete_option( $threat['option_name'] );
            // Also handle _wpv% meta tables
            foreach ( array( $wpdb->postmeta, $wpdb->usermeta, $wpdb->termmeta, $wpdb->commentmeta ) as $table ) {
                $pk = ( $table === $wpdb->usermeta ) ? 'umeta_id' : 'meta_id';
                $rows = $wpdb->get_col( $wpdb->prepare( "SELECT {$pk} FROM {$table} WHERE meta_key LIKE %s AND LENGTH(meta_value) > 500", '_wpv%' ) );
                foreach ( $rows as $id ) {
                    $wpdb->delete( $table, array( $pk => $id ) );
                }
            }
            return array( 'ok' => true, 'message' => 'Deleted DB entry: ' . esc_html( $threat['option_name'] ) );
        }

        // Meta table cleanup (threat has no option_name but mentions meta table)
        if ( strpos( $threat['location'], 'meta table' ) !== false ) {
            $total = 0;
            foreach ( array( $wpdb->postmeta, $wpdb->usermeta, $wpdb->termmeta, $wpdb->commentmeta ) as $table ) {
                $pk   = ( $table === $wpdb->usermeta ) ? 'umeta_id' : 'meta_id';
                $rows = $wpdb->get_col( $wpdb->prepare( "SELECT {$pk} FROM {$table} WHERE meta_key LIKE %s AND LENGTH(meta_value) > 500", '_wpv%' ) );
                foreach ( $rows as $id ) {
                    $wpdb->delete( $table, array( $pk => $id ) );
                    $total++;
                }
            }
            return array( 'ok' => true, 'message' => "Deleted {$total} meta payload row(s)" );
        }

        return array( 'ok' => false, 'message' => 'No option_name in threat data — cannot remove.' );
    }

    // ── Cron removal ──────────────────────────────────────────────────

    private static function remove_cron( $threat ) {
        if ( empty( $threat['cron_hook'] ) ) {
            return array( 'ok' => false, 'message' => 'No cron hook in threat data.' );
        }
        $hook = $threat['cron_hook'];
        $ts   = wp_next_scheduled( $hook );
        if ( $ts ) {
            wp_unschedule_event( $ts, $hook );
            wp_clear_scheduled_hook( $hook );
        }
        return array( 'ok' => true, 'message' => 'Removed cron job: ' . esc_html( $hook ) );
    }

    // ── User removal ──────────────────────────────────────────────────

    private static function remove_user( $threat ) {
        if ( empty( $threat['username'] ) ) {
            return array( 'ok' => false, 'message' => 'No username in threat data.' );
        }
        $uid = username_exists( $threat['username'] );
        if ( ! $uid ) {
            return array( 'ok' => true, 'message' => 'User already gone: ' . esc_html( $threat['username'] ) );
        }
        if ( ! function_exists( 'wp_delete_user' ) ) {
            require_once ABSPATH . 'wp-admin/includes/user.php';
        }
        wp_delete_user( $uid, get_current_user_id() );
        return array( 'ok' => true, 'message' => 'Deleted backdoor user: ' . esc_html( $threat['username'] ) );
    }
}
