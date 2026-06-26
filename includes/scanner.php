<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Shield Security Scanner — chunked AJAX steps, PHP 7.0 compatible
 *
 * Each scan step runs as its own AJAX request so no single request
 * can hit a server timeout. The browser drives the sequence.
 *
 * Steps (in order):
 *  1. mu_plugins      — scan wp-content/mu-plugins/
 *  2. plugins         — scan wp-content/plugins/
 *  3. themes          — scan active + parent theme
 *  4. dropins         — advanced-cache.php, db.php, object-cache.php, wp-login.php
 *  5. scatter         — /fonts, /cache, /upgrade, /languages (RAT scatter dirs)
 *  6. uploads         — fake JPEG credential logs
 *  7. database        — wp_options patterns + payload blobs + meta tables
 *  8. system          — cron jobs + known backdoor admin users
 *  9. finalise        — merge partial results, save, send alert if needed
 */
class Shield_Scanner {

    // ── Signatures ────────────────────────────────────────────────────

    private static $file_signatures = array(
        '_ac_23da9d25', '_ac_07d0b218', '_wpc_375586e3', '_ac_ce79ae25',
        'wp_15384834c4_cfg', 'Opt_Service_002e',
        'base64_decode(gzinflate', 'eval(base64_decode', 'eval(gzinflate',
        'str_rot13(base64', '$_POST[chr(', 'assert(base64',
        'preg_replace("/.*/e"', 'create_function(',
        'shell_exec($_', 'system($_', 'passthru($_', 'exec($_',
    );

    private static $db_signatures = array(
        '_site_health_scan_config%', '_site_login_attempt_log%',
        'taxonomy_cache_flush_%', '_ac_23da9d25%', '_ac_07d0b218%',
        '_wpc_375586e3%', '_ac_ce79ae25%', '_core_version_check_hash%',
        '_site_auth_tokens_hash%', '_wph_5945%', '_wpc_f4bd6e7c%',
        '_wp_rewrite_rules_cache%', '_wp_login_session_data%',
        '_wp_core_settings_cache%', '_wpc_0b8206e3%', '_wph_2e29%', '_wpv%',
        '_core_integrity_hash%', '_wp_auth_cookie_cache%',
        '_site_compatibility_data%', 'wp_15384834c4_cfg',
        'role_cache_rebuild_%', 'site_optimization_scan_%',
    );

    private static $heuristic_patterns = array(
        '/\beval\s*\(\s*base64_decode\s*\(/'            => 'eval+base64_decode (common obfuscation)',
        '/\beval\s*\(\s*gzinflate\s*\(/'                => 'eval+gzinflate (compressed payload)',
        '/\beval\s*\(\s*str_rot13\s*\(/'                => 'eval+str_rot13 (obfuscation)',
        '/base64_decode\s*\([\'"][A-Za-z0-9+\/]{500,}/' => 'large inline base64 blob (>500 chars)',
        '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+/'  => 'char-by-char string construction',
        '/add_action\s*\(\s*[\'"]wp_footer[\'"].*\d{5,}/' => 'wp_footer hook with very high priority',
        '/preg_replace\s*\([\'"]\/.*\/e[\'"]/'          => 'preg_replace /e modifier (code execution)',
        '/create_function\s*\(/'                        => 'create_function (deprecated, often malicious)',
        '/_0x[0-9a-f]{4,}\s*=/'                        => 'hex-named JS variable (obfuscated JS)',
        '/String\.fromCharCode\s*\(/'                   => 'JS String.fromCharCode (obfuscated output)',
    );

    private static $scan_extensions = array( 'php', 'js', 'html', 'htm' );
    private static $skip_dirs       = array( 'node_modules', '.git', 'wp-content/uploads/sites' );

    // ── Step definitions (used by UI to build the progress list) ─────

    public static function get_steps() {
        return array(
            'mu_plugins' => 'MU Plugins',
            'plugins'    => 'Plugins Folder',
            'themes'     => 'Active Theme',
            'dropins'    => 'Drop-in Files & wp-login.php',
            'scatter'    => 'RAT Scatter Directories',
            'uploads'    => 'Uploads (Fake JPEG Logs)',
            'database'   => 'Database (wp_options)',
            'system'     => 'Cron Jobs & Admin Users',
            'finalise'   => 'Finalise & Save Results',
        );
    }

    // ── Session helpers ───────────────────────────────────────────────
    // Partial results are accumulated in a transient during the scan
    // so each AJAX step can read and append to them.

    private static function get_partial() {
        $data = get_transient( 'shield_scan_partial' );
        if ( ! is_array( $data ) ) {
            $data = array(
                'started_at'      => current_time( 'mysql' ),
                'threats'         => array(),
                'files_scanned'   => 0,
                'db_rows_scanned' => 0,
                'steps_done'      => array(),
            );
        }
        return $data;
    }

    private static function save_partial( $data ) {
        // Keep transient alive for up to 30 minutes
        set_transient( 'shield_scan_partial', $data, 30 * MINUTE_IN_SECONDS );
    }

    private static function clear_partial() {
        delete_transient( 'shield_scan_partial' );
    }

    // ── Public: run one step ──────────────────────────────────────────

    public static function run_step( $step ) {
        // Extend PHP time limit per step (ignored on some hosts but helps)
        @set_time_limit( 60 );

        $partial = self::get_partial();

        // Don't re-run a step that already completed
        if ( in_array( $step, $partial['steps_done'], true ) ) {
            return array(
                'ok'            => true,
                'step'          => $step,
                'already_done'  => true,
                'threats_found' => 0,
                'files_scanned' => 0,
            );
        }

        $threats_before = count( $partial['threats'] );
        $files_before   = $partial['files_scanned'];
        $start          = microtime( true );

        switch ( $step ) {
            case 'mu_plugins':
                self::scan_directory( WPMU_PLUGIN_DIR, $partial );
                break;

            case 'plugins':
                self::scan_directory( WP_PLUGIN_DIR, $partial );
                break;

            case 'themes':
                self::scan_directory( get_template_directory(), $partial );
                $child = get_stylesheet_directory();
                if ( $child !== get_template_directory() ) {
                    self::scan_directory( $child, $partial );
                }
                break;

            case 'dropins':
                $dropin_files = array(
                    WP_CONTENT_DIR . '/advanced-cache.php',
                    WP_CONTENT_DIR . '/db.php',
                    WP_CONTENT_DIR . '/object-cache.php',
                    ABSPATH . 'wp-login.php',
                );
                foreach ( $dropin_files as $path ) {
                    self::scan_file_if_exists( $path, $partial );
                }
                break;

            case 'scatter':
                $scatter_dirs = array( 'fonts', 'cache', 'upgrade', 'languages' );
                foreach ( $scatter_dirs as $dir ) {
                    $path = WP_CONTENT_DIR . '/' . $dir;
                    if ( is_dir( $path ) ) {
                        self::scan_directory( $path, $partial, 1 );
                    }
                }
                break;

            case 'uploads':
                self::scan_fake_jpgs( $partial );
                break;

            case 'database':
                self::scan_database( $partial );
                break;

            case 'system':
                self::scan_system( $partial );
                break;

            case 'finalise':
                self::finalise( $partial );
                self::clear_partial();
                return array(
                    'ok'            => true,
                    'step'          => $step,
                    'threats_found' => count( $partial['threats'] ),
                    'files_scanned' => $partial['files_scanned'],
                    'time'          => round( microtime( true ) - $start, 2 ),
                    'final'         => true,
                    'threat_count'  => count( $partial['threats'] ),
                );
        }

        $partial['steps_done'][] = $step;
        self::save_partial( $partial );

        return array(
            'ok'            => true,
            'step'          => $step,
            'threats_found' => count( $partial['threats'] ) - $threats_before,
            'files_scanned' => $partial['files_scanned'] - $files_before,
            'total_threats' => count( $partial['threats'] ),
            'time'          => round( microtime( true ) - $start, 2 ),
        );
    }

    // ── Backwards-compat: full scan in one call (used by WP-CLI etc.) ─

    public static function run_scan( $options = array() ) {
        self::clear_partial();
        $steps = array_keys( self::get_steps() );
        foreach ( $steps as $step ) {
            self::run_step( $step );
        }
        return get_option( 'shield_last_scan', array() );
    }

    // ── Finalise: merge partial → last_scan option ────────────────────

    private static function finalise( &$partial ) {
        $results = array(
            'started_at'      => $partial['started_at'],
            'completed_at'    => current_time( 'mysql' ),
            'threats'         => $partial['threats'],
            'files_scanned'   => $partial['files_scanned'],
            'db_rows_scanned' => $partial['db_rows_scanned'],
            'threat_count'    => count( $partial['threats'] ),
            'scan_time'       => 0, // individual step times shown in UI
        );

        update_option( 'shield_last_scan', $results );

        $count = $results['threat_count'];
        $msg   = 'Scan complete. ' . $count . ' threat(s) found.';
        shield_log( $msg, $count > 0 ? 'warn' : 'info' );

        if ( $count > 0 ) {
            $body  = "Shield Security detected {$count} threat(s) on " . home_url() . ".\n\n";
            $body .= "Scan completed: {$results['completed_at']}\n\n";
            foreach ( $results['threats'] as $t ) {
                $body .= '- [' . $t['type'] . '] ' . $t['location'] . ': ' . $t['description'] . "\n";
            }
            $body .= "\nLog in to wp-admin > Shield Security to review and clean.";
            shield_send_alert( $count . ' threat(s) detected', $body );
        }
    }

    // ── File scanning ─────────────────────────────────────────────────

    private static function scan_directory( $dir, &$partial, $max_depth = 10, $depth = 0 ) {
        if ( ! is_dir( $dir ) || $depth > $max_depth ) return;

        $base = basename( $dir );
        foreach ( self::$skip_dirs as $skip ) {
            if ( $base === $skip || strpos( $dir, $skip ) !== false ) return;
        }

        $handle = @opendir( $dir );
        if ( ! $handle ) return;

        while ( ( $item = readdir( $handle ) ) !== false ) {
            if ( $item === '.' || $item === '..' ) continue;
            $path = $dir . '/' . $item;
            if ( is_dir( $path ) ) {
                self::scan_directory( $path, $partial, $max_depth, $depth + 1 );
            } elseif ( is_file( $path ) ) {
                $ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
                if ( in_array( $ext, self::$scan_extensions, true ) ) {
                    self::scan_file( $path, $partial );
                }
            }
        }
        closedir( $handle );
    }

    private static function scan_file_if_exists( $path, &$partial ) {
        if ( file_exists( $path ) ) self::scan_file( $path, $partial );
    }

    private static function scan_file( $path, &$partial ) {
        $partial['files_scanned']++;
        $content = @file_get_contents( $path );
        if ( $content === false || strlen( $content ) === 0 ) return;

        $rel = str_replace( ABSPATH, '', $path );

        foreach ( self::$file_signatures as $sig ) {
            if ( strpos( $content, $sig ) !== false ) {
                $partial['threats'][] = array(
                    'type'        => 'signature',
                    'severity'    => 'critical',
                    'location'    => $rel,
                    'description' => 'Known malware signature: ' . $sig,
                    'file'        => $path,
                );
                return;
            }
        }

        $ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
        if ( $ext === 'php' ) {
            foreach ( self::$heuristic_patterns as $pattern => $desc ) {
                if ( @preg_match( $pattern, $content ) ) {
                    $partial['threats'][] = array(
                        'type'        => 'heuristic',
                        'severity'    => 'warning',
                        'location'    => $rel,
                        'description' => 'Suspicious pattern: ' . $desc,
                        'file'        => $path,
                    );
                    break;
                }
            }
        }
    }

    private static function scan_fake_jpgs( &$partial ) {
        $upload_dir = WP_CONTENT_DIR . '/uploads/';
        for ( $i = 0; $i <= 5; $i++ ) {
            $ts  = strtotime( '-' . $i . ' months' );
            $dir = $upload_dir . date( 'Y', $ts ) . '/' . date( 'm', $ts ) . '/';
            if ( ! is_dir( $dir ) ) continue;
            $files = glob( $dir . 'gallery-thumb-????????.jpg' );
            if ( ! $files ) continue;
            foreach ( $files as $file ) {
                $bytes = @file_get_contents( $file, false, null, 0, 200 );
                if ( ! $bytes || substr( $bytes, 0, 4 ) !== "\xFF\xD8\xFF\xE0" ) continue;
                $fc = @file_get_contents( $file );
                if ( $fc && preg_match( '/\d{10}\|[\d\.]+\|https?:\/\//', $fc ) ) {
                    $partial['threats'][] = array(
                        'type'        => 'credential_log',
                        'severity'    => 'critical',
                        'location'    => str_replace( ABSPATH, '', $file ),
                        'description' => 'Fake JPEG credential log — contains harvested login data',
                        'file'        => $file,
                    );
                }
            }
        }
    }

    // ── Database scanning ─────────────────────────────────────────────

    private static function scan_database( &$partial ) {
        global $wpdb;

        foreach ( self::$db_signatures as $pattern ) {
            $rows = $wpdb->get_results( $wpdb->prepare(
                "SELECT option_name, LENGTH(option_value) AS vlen FROM {$wpdb->options} WHERE option_name LIKE %s",
                $pattern
            ) );
            foreach ( $rows as $row ) {
                $partial['db_rows_scanned']++;
                $partial['threats'][] = array(
                    'type'        => 'database',
                    'severity'    => 'critical',
                    'location'    => 'wp_options: ' . $row->option_name,
                    'description' => 'Known malware option key (' . number_format( $row->vlen ) . ' bytes)',
                    'option_name' => $row->option_name,
                );
            }
        }

        $blobs = $wpdb->get_results(
            "SELECT option_name, LENGTH(option_value) AS vlen FROM {$wpdb->options}
             WHERE LENGTH(option_value) > 5000 AND option_value LIKE 'PD9waH%'"
        );
        foreach ( $blobs as $row ) {
            $partial['db_rows_scanned']++;
            $partial['threats'][] = array(
                'type'        => 'database',
                'severity'    => 'critical',
                'location'    => 'wp_options: ' . $row->option_name,
                'description' => 'PHP payload blob in database (' . number_format( $row->vlen ) . ' bytes)',
                'option_name' => $row->option_name,
            );
        }

        $js_blobs = $wpdb->get_results(
            "SELECT option_name, LENGTH(option_value) AS vlen FROM {$wpdb->options}
             WHERE LENGTH(option_value) > 2000
             AND ( option_value LIKE 'KGZ1bmN0%' OR option_value LIKE 'dmFyIF8%' OR option_value LIKE 'KHZhciB%' )"
        );
        $safe_prefixes = array( 'wp_user_roles', 'rewrite_rules', 'widget_', 'sidebars_widgets', 'elementor' );
        foreach ( $js_blobs as $row ) {
            $is_safe = false;
            foreach ( $safe_prefixes as $s ) {
                if ( strpos( $row->option_name, $s ) !== false ) { $is_safe = true; break; }
            }
            if ( ! $is_safe ) {
                $partial['db_rows_scanned']++;
                $partial['threats'][] = array(
                    'type'        => 'database',
                    'severity'    => 'critical',
                    'location'    => 'wp_options: ' . $row->option_name,
                    'description' => 'Obfuscated JS payload blob (' . number_format( $row->vlen ) . ' bytes)',
                    'option_name' => $row->option_name,
                );
            }
        }

        $meta_tables = array(
            $wpdb->postmeta    => 'meta_id',
            $wpdb->usermeta    => 'umeta_id',
            $wpdb->termmeta    => 'meta_id',
            $wpdb->commentmeta => 'meta_id',
        );
        foreach ( $meta_tables as $table => $pk ) {
            $count = (int) $wpdb->get_var( $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table} WHERE meta_key LIKE %s AND LENGTH(meta_value) > 500",
                '_wpv%'
            ) );
            if ( $count > 0 ) {
                $partial['db_rows_scanned'] += $count;
                $partial['threats'][] = array(
                    'type'        => 'database',
                    'severity'    => 'critical',
                    'location'    => $table . ' (meta table)',
                    'description' => $count . ' malware payload row(s) matching _wpv% pattern',
                );
            }
        }
    }

    // ── System scanning (cron + users) ────────────────────────────────

    private static function scan_system( &$partial ) {
        $known_cron_hooks = array(
            'taxonomy_cache_flush_c30d',
            'role_cache_rebuild_0958',
            'site_optimization_scan_76cc',
        );
        foreach ( $known_cron_hooks as $hook ) {
            if ( wp_next_scheduled( $hook ) ) {
                $partial['threats'][] = array(
                    'type'        => 'cron',
                    'severity'    => 'critical',
                    'location'    => 'WP Cron: ' . $hook,
                    'description' => 'Known malware cron job is scheduled',
                    'cron_hook'   => $hook,
                );
            }
        }

        $known_backdoor_users = array( 'siteadmin', 'techsupport', 'wpmanager', 'wpadmin99' );
        foreach ( $known_backdoor_users as $login ) {
            if ( username_exists( $login ) ) {
                $partial['threats'][] = array(
                    'type'        => 'user',
                    'severity'    => 'critical',
                    'location'    => 'wp_users: ' . $login,
                    'description' => 'Known backdoor admin account exists: ' . $login,
                    'username'    => $login,
                );
            }
        }
    }

    public static function get_last_scan() {
        return get_option( 'shield_last_scan', null );
    }
}
