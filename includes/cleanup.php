<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Shield_Cleanup {

    /**
     * Remove a single threat. Returns array( 'ok' => bool, 'message' => string )
     * SAFETY: Always checks shield_path_is_excluded() before touching any file.
     */
    public static function remove_threat( $threat ) {
        $type = isset( $threat['type'] ) ? $threat['type'] : '';
        switch ( $type ) {
            case 'signature':
            case 'heuristic':
            case 'fake_jpg':
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

    public static function remove_all( $threats ) {
        $log = array();
        foreach ( $threats as $threat ) {
            $result  = self::remove_threat( $threat );
            $log[]   = $result;
            shield_log( $result['message'], $result['ok'] ? 'info' : 'warn' );
        }
        return $log;
    }

    // ── File removal ─────────────────────────────────────────────────

    private static function remove_file( $threat ) {
        if ( empty( $threat['file'] ) ) {
            return array( 'ok' => false, 'message' => 'No file path in threat data.' );
        }
        $path = $threat['file'];

        // SAFETY: never delete own plugin files
        if ( shield_path_is_excluded( $path ) ) {
            return array( 'ok' => false, 'message' => 'Skipped (excluded path): ' . esc_html( $threat['location'] ) );
        }

        if ( ! file_exists( $path ) ) {
            return array( 'ok' => true, 'message' => 'Already removed: ' . esc_html( $threat['location'] ) );
        }

        // Drop-in files may have legitimate content — strip injection rather than delete
        $dropin_names = array( 'advanced-cache.php', 'db.php', 'object-cache.php' );
        if ( in_array( basename( $path ), $dropin_names, true ) ) {
            return self::strip_dropin( $path, $threat );
        }

        if ( @unlink( $path ) ) {
            return array( 'ok' => true, 'message' => 'Deleted: ' . esc_html( $threat['location'] ) );
        }
        return array( 'ok' => false, 'message' => 'Could not delete (check permissions): ' . esc_html( $threat['location'] ) );
    }

    private static function strip_dropin( $path, $threat ) {
        $content = @file_get_contents( $path );
        if ( ! $content ) return array( 'ok' => false, 'message' => 'Cannot read: ' . esc_html( $threat['location'] ) );

        $sigs = array(
            '_ac_'  . '23da9d25',
            '_ac_'  . '07d0b218',
            '_wpc_' . '375586e3',
            '_ac_'  . 'ce79ae25',
            '_wpc_0b' . '8206e3',
        );
        $sig_found = '';
        foreach ( $sigs as $s ) {
            if ( strpos( $content, $s ) !== false ) { $sig_found = $s; break; }
        }

        $is_malware_only = strpos( $content, 'WordPress Advanced Cache Plugin' ) !== false
                        || strpos( $content, 'WordPress Database Abstraction' ) !== false
                        || strpos( $content, 'WordPress Object Cache' ) !== false;

        if ( $is_malware_only ) {
            if ( @unlink( $path ) ) return array( 'ok' => true, 'message' => 'Deleted malware drop-in: ' . esc_html( $threat['location'] ) );
            return array( 'ok' => false, 'message' => 'Cannot delete drop-in: ' . esc_html( $threat['location'] ) );
        }

        if ( $sig_found ) {
            $clean = rtrim( substr( $content, 0, strpos( $content, $sig_found ) ) );
            if ( @file_put_contents( $path, $clean ) ) return array( 'ok' => true, 'message' => 'Stripped injection from: ' . esc_html( $threat['location'] ) );
            return array( 'ok' => false, 'message' => 'Cannot write cleaned file: ' . esc_html( $threat['location'] ) );
        }

        return array( 'ok' => false, 'message' => 'Could not isolate injection — review manually: ' . esc_html( $threat['location'] ) );
    }

    // ── Database removal ─────────────────────────────────────────────

    private static function remove_db_option( $threat ) {
        global $wpdb;
        if ( ! empty( $threat['option_name'] ) ) {
            delete_option( $threat['option_name'] );
            return array( 'ok' => true, 'message' => 'Deleted DB entry: ' . esc_html( $threat['option_name'] ) );
        }
        if ( strpos( $threat['location'], 'meta table' ) !== false ) {
            $total = 0;
            foreach ( array( $wpdb->postmeta, $wpdb->usermeta, $wpdb->termmeta, $wpdb->commentmeta ) as $table ) {
                $pk   = ( $table === $wpdb->usermeta ) ? 'umeta_id' : 'meta_id';
                $rows = $wpdb->get_col( $wpdb->prepare( "SELECT {$pk} FROM {$table} WHERE meta_key LIKE %s AND LENGTH(meta_value) > 500", '_wpv%' ) );
                foreach ( $rows as $id ) { $wpdb->delete( $table, array( $pk => $id ) ); $total++; }
            }
            return array( 'ok' => true, 'message' => "Deleted {$total} meta payload row(s)" );
        }
        return array( 'ok' => false, 'message' => 'No option_name in threat data.' );
    }

    // ── Cron removal ─────────────────────────────────────────────────

    private static function remove_cron( $threat ) {
        if ( empty( $threat['cron_hook'] ) ) return array( 'ok' => false, 'message' => 'No cron hook in threat.' );
        $hook = $threat['cron_hook'];
        $ts   = wp_next_scheduled( $hook );
        if ( $ts ) { wp_unschedule_event( $ts, $hook ); wp_clear_scheduled_hook( $hook ); }
        return array( 'ok' => true, 'message' => 'Removed cron: ' . esc_html( $hook ) );
    }

    // ── User removal ─────────────────────────────────────────────────

    private static function remove_user( $threat ) {
        if ( empty( $threat['username'] ) ) return array( 'ok' => false, 'message' => 'No username in threat.' );
        $uid = username_exists( $threat['username'] );
        if ( ! $uid ) return array( 'ok' => true, 'message' => 'User already gone: ' . esc_html( $threat['username'] ) );
        if ( ! function_exists( 'wp_delete_user' ) ) require_once ABSPATH . 'wp-admin/includes/user.php';
        wp_delete_user( $uid, get_current_user_id() );
        return array( 'ok' => true, 'message' => 'Deleted user: ' . esc_html( $threat['username'] ) );
    }
}
