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
            case 'webshell':
            case 'decoy_plugin':
            case 'payload_binary':
                // If a file is marked as surgically cleanable, remove injection only
                if ( ! empty( $threat['surgical'] ) ) {
                    return self::remove_injection( $threat );
                }
                return self::remove_file( $threat );
            case 'injection':
                return self::remove_injection( $threat );
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
    // ── Surgical injection removal ────────────────────────────────────────
    // Instead of deleting an entire file (which could crash the site),
    // this method removes only the specific injected lines that contain
    // known malware patterns. Safe for core files like wp-login.php,
    // plugin files with injected code, and any file too important to delete.

    // Known injection patterns — each is a regex that matches an injected line.
    // When found, the ENTIRE LINE containing the match is removed.
    private static function get_injection_patterns() {
        return array(
            // Script tag loading known C2 domains
            "#<script[^>]+src=[^>]*(interseq\.at|webanalytics-cdn\.sbs|dome\.369bbq)[^>]*></script>#i",
            // wp_enqueue_script with known C2 URL
            "#wp_enqueue_script[^;]*(interseq\.at|webanalytics-cdn\.sbs)[^;]*;#",
            // Inline script tag referencing C2
            "#<script[^>]*>[^<]*(interseq\.at|webanalytics-cdn\.sbs)[^<]*</script>#i",
            // dns-prefetch for C2 domains
            "#<link[^>]+dns-prefetch[^>]*(interseq\.at|webanalytics-cdn\.sbs)[^>]*>#i",
            // wordpress-defender script ID
            "#wp_enqueue_script[^;]*wordpress-defender-389[^;]*;#",
            // login_enqueue_scripts hook from wordpress-defender class
            "#add_action\s*\(\s*[^,]+login_enqueue_scripts[^;]+enqueue_front[^;]+;#",
        );
    }

    public static function remove_injection( $threat ) {
        if ( empty( $threat['file'] ) ) {
            return array( 'ok' => false, 'message' => 'No file path in threat data.' );
        }
        $path = $threat['file'];

        if ( shield_path_is_excluded( $path ) ) {
            return array( 'ok' => false, 'message' => 'Skipped (excluded path).' );
        }
        if ( ! file_exists( $path ) ) {
            return array( 'ok' => true, 'message' => 'Already removed: ' . esc_html( $threat['location'] ) );
        }
        if ( ! is_writable( $path ) ) {
            return array( 'ok' => false, 'message' => 'File not writable: ' . esc_html( $threat['location'] ) );
        }

        $original = @file_get_contents( $path );
        if ( $original === false ) {
            return array( 'ok' => false, 'message' => 'Cannot read file: ' . esc_html( $threat['location'] ) );
        }

        // Backup first
        $backup_dir = WP_CONTENT_DIR . '/shield-backups/';
        if ( ! is_dir( $backup_dir ) ) {
            @mkdir( $backup_dir, 0755, true );
        }
        $backup_path = $backup_dir . basename( $path ) . '.' . date( 'YmdHis' ) . '.bak';
        @file_put_contents( $backup_path, $original );

        $cleaned  = $original;
        $removed  = array();

        // Strategy 1: Match known injection patterns (regex line removal)
        foreach ( self::get_injection_patterns() as $pattern ) {
            if ( @preg_match( $pattern, $cleaned ) ) {
                $new = preg_replace( $pattern, '', $cleaned );
                if ( $new !== null && $new !== $cleaned ) {
                    $removed[] = 'Injection pattern removed';
                    $cleaned   = $new;
                }
            }
        }

        // Strategy 2: Line-by-line scan for known malware strings
        // Removes entire lines containing known C2 domains or malware markers
        $malware_strings = array(
            'interseq.at',
            'webanalytics-cdn.sbs',
            'dome.369bbq',
            'wordpress-defender-389',
            'Wordpress_Defender_Core_54',
            '_wp_cron_lock_status',
            'wp_set_auth_cookie($u->ID',
            'role-cache.php',
        );

        $lines     = explode( "
", $cleaned );
        $new_lines = array();
        $line_hits = 0;
        foreach ( $lines as $line ) {
            $hit = false;
            foreach ( $malware_strings as $marker ) {
                if ( strpos( $line, $marker ) !== false ) {
                    $hit = true;
                    $line_hits++;
                    $removed[] = 'Line removed: ' . trim( substr( $line, 0, 80 ) );
                    break;
                }
            }
            if ( ! $hit ) $new_lines[] = $line;
        }
        $cleaned = implode( "
", $new_lines );

        // Safety check: cleaned file must not be empty or tiny
        if ( strlen( $cleaned ) < 100 && strlen( $original ) > 500 ) {
            return array(
                'ok'      => false,
                'message' => 'Surgical removal aborted — result would be too small. Delete manually via SFTP.',
            );
        }

        if ( empty( $removed ) ) {
            return array(
                'ok'      => false,
                'message' => 'No injected code found to remove in: ' . esc_html( $threat['location'] ) . '. File may have already been cleaned.',
            );
        }

        // Write cleaned file
        $result = @file_put_contents( $path, $cleaned );
        if ( $result === false ) {
            return array( 'ok' => false, 'message' => 'Could not write cleaned file.' );
        }

        shield_log( 'Surgical cleanup: ' . count( $removed ) . ' injection(s) removed from ' . $threat['location'], 'info' );

        return array(
            'ok'      => true,
            'message' => 'Injection removed from ' . esc_html( $threat['location'] ) . ' (' . count( $removed ) . ' line(s) cleaned). Backup saved to shield-backups/.',
            'removed' => $removed,
            'backup'  => $backup_path,
        );
    }


}