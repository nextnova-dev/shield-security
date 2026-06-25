<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Deep malware scanner — PHP 7.0 compatible
 * Scans files and database for known malware signatures + heuristic patterns
 */
class Shield_Scanner {

    // Known malware file signatures (from all 5 variants analyzed)
    private static $file_signatures = array(
        // RAT family — drop-in injection signatures
        '_ac_23da9d25', '_ac_07d0b218', '_wpc_375586e3', '_ac_ce79ae25',
        // RAT family — known payload identifiers
        'wp_15384834c4_cfg', 'Opt_Service_002e',
        // Common malware patterns
        'base64_decode(gzinflate', 'eval(base64_decode', 'eval(gzinflate',
        'str_rot13(base64', '$_POST[chr(', 'assert(base64',
        'preg_replace("/.*/e"', 'create_function(',
        // Credential harvester marker
        'gallery-thumb-', 'JFIF' . "\x00\x01",
        // Shell markers
        'shell_exec($_', 'system($_', 'passthru($_', 'exec($_',
        // JS injector family
        'wp_footer.*96786', 'Opt_Service_002e',
    );

    // Known malware option key patterns in wp_options
    private static $db_signatures = array(
        '_site_health_scan_config%',
        '_site_login_attempt_log%',
        'taxonomy_cache_flush_%',
        '_ac_23da9d25%',
        '_ac_07d0b218%',
        '_wpc_375586e3%',
        '_ac_ce79ae25%',
        '_core_version_check_hash%',
        '_site_auth_tokens_hash%',
        '_wph_5945%',
        '_wpc_f4bd6e7c%',
        '_wp_rewrite_rules_cache%',
        '_wp_login_session_data%',
        '_wp_core_settings_cache%',
        '_wpc_0b8206e3%',
        '_wph_2e29%',
        '_wpv%',
        '_core_integrity_hash%',
        '_wp_auth_cookie_cache%',
        '_site_compatibility_data%',
        'wp_15384834c4_cfg',
        'role_cache_rebuild_%',
        'site_optimization_scan_%',
    );

    // Heuristic patterns (regex) for file content scanning
    private static $heuristic_patterns = array(
        '/\beval\s*\(\s*base64_decode\s*\(/'           => 'eval+base64_decode (common obfuscation)',
        '/\beval\s*\(\s*gzinflate\s*\(/'               => 'eval+gzinflate (compressed payload)',
        '/\beval\s*\(\s*str_rot13\s*\(/'               => 'eval+str_rot13 (obfuscation)',
        '/base64_decode\s*\([\'"][A-Za-z0-9+\/]{500,}/'=> 'large inline base64 blob (>500 chars)',
        '/\\$[a-zA-Z_]\w*\s*\(\s*\\$[a-zA-Z_]\w*\s*,\s*\\$[a-zA-Z_]\w*/' => 'variable function call pattern',
        '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+/' => 'char-by-char string construction',
        '/add_action\s*\(\s*[\'"]wp_footer[\'"].*\d{5,}/' => 'wp_footer hook with suspiciously high priority',
        '/preg_replace\s*\([\'"]\/.*\/e[\'"]/'         => 'preg_replace /e modifier (code execution)',
        '/create_function\s*\(/'                       => 'create_function (deprecated, often malicious)',
        '/_0x[0-9a-f]{4,}\s*=/'                       => 'hex-named JS variable (obfuscated JS)',
        '/String\.fromCharCode\s*\(/'                  => 'JS String.fromCharCode (obfuscated output)',
    );

    // File extensions to scan
    private static $scan_extensions = array( 'php', 'js', 'html', 'htm' );

    // Directories to always skip
    private static $skip_dirs = array(
        'node_modules', '.git', 'wp-content/uploads/sites',
    );

    /**
     * Run a full scan. Returns results array.
     */
    public static function run_scan( $options = array() ) {
        $defaults = array(
            'scan_files'    => true,
            'scan_db'       => true,
            'scan_plugins'  => true,
            'scan_themes'   => true,
            'scan_mu'       => true,
            'scan_core'     => false,  // Core file integrity — slower
        );
        $options = array_merge( $defaults, $options );

        $results = array(
            'started_at'     => current_time( 'mysql' ),
            'threats'        => array(),
            'files_scanned'  => 0,
            'db_rows_scanned'=> 0,
            'scan_time'      => 0,
        );

        $start = microtime( true );

        if ( $options['scan_files'] ) {
            // Scan mu-plugins
            if ( $options['scan_mu'] ) {
                self::scan_directory( WPMU_PLUGIN_DIR, $results );
            }
            // Scan plugins
            if ( $options['scan_plugins'] ) {
                self::scan_directory( WP_PLUGIN_DIR, $results );
            }
            // Scan active theme + parent theme
            if ( $options['scan_themes'] ) {
                self::scan_directory( get_template_directory(), $results );
                $child = get_stylesheet_directory();
                if ( $child !== get_template_directory() ) {
                    self::scan_directory( $child, $results );
                }
            }
            // Scan wp-content root (drop-ins)
            self::scan_file_if_exists( WP_CONTENT_DIR . '/advanced-cache.php', $results );
            self::scan_file_if_exists( WP_CONTENT_DIR . '/db.php', $results );
            self::scan_file_if_exists( WP_CONTENT_DIR . '/object-cache.php', $results );
            // Scan wp-login.php
            self::scan_file_if_exists( ABSPATH . 'wp-login.php', $results );
            // Scan scatter locations used by known RAT family
            $scatter_dirs = array( 'fonts', 'cache', 'upgrade', 'languages' );
            foreach ( $scatter_dirs as $dir ) {
                $path = WP_CONTENT_DIR . '/' . $dir;
                if ( is_dir( $path ) ) {
                    self::scan_directory( $path, $results, 1 );  // shallow
                }
            }
            // Scan uploads for fake JPEGs
            self::scan_fake_jpgs( $results );
        }

        if ( $options['scan_db'] ) {
            self::scan_database( $results );
        }

        $results['scan_time']    = round( microtime( true ) - $start, 2 );
        $results['completed_at'] = current_time( 'mysql' );
        $results['threat_count'] = count( $results['threats'] );

        // Save results
        update_option( 'shield_last_scan', $results );

        // Log and alert
        $msg = 'Scan complete. ' . $results['threat_count'] . ' threat(s) found. Time: ' . $results['scan_time'] . 's';
        shield_log( $msg, $results['threat_count'] > 0 ? 'warn' : 'info' );

        if ( $results['threat_count'] > 0 ) {
            $body  = "Shield Security detected {$results['threat_count']} threat(s) on " . home_url() . ".\n\n";
            $body .= "Scan completed at: {$results['completed_at']}\n\n";
            foreach ( $results['threats'] as $t ) {
                $body .= "- [{$t['type']}] {$t['location']}: {$t['description']}\n";
            }
            $body .= "\nLog in to wp-admin > Shield Security to review and clean.";
            shield_send_alert( $results['threat_count'] . ' threat(s) detected', $body );
        }

        return $results;
    }

    // ── File scanning ─────────────────────────────────────────────────

    private static function scan_directory( $dir, &$results, $max_depth = 10, $depth = 0 ) {
        if ( ! is_dir( $dir ) || $depth > $max_depth ) return;

        // Check skip list
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
                self::scan_directory( $path, $results, $max_depth, $depth + 1 );
            } elseif ( is_file( $path ) ) {
                $ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
                if ( in_array( $ext, self::$scan_extensions, true ) ) {
                    self::scan_file( $path, $results );
                }
            }
        }
        closedir( $handle );
    }

    private static function scan_file_if_exists( $path, &$results ) {
        if ( file_exists( $path ) ) self::scan_file( $path, $results );
    }

    private static function scan_file( $path, &$results ) {
        $results['files_scanned']++;
        $content = @file_get_contents( $path );
        if ( $content === false || strlen( $content ) === 0 ) return;

        $rel = str_replace( ABSPATH, '', $path );

        // Signature check
        foreach ( self::$file_signatures as $sig ) {
            if ( strpos( $content, $sig ) !== false ) {
                $results['threats'][] = array(
                    'type'        => 'signature',
                    'severity'    => 'critical',
                    'location'    => $rel,
                    'description' => 'Known malware signature: ' . esc_html( $sig ),
                    'file'        => $path,
                );
                return; // One threat per file is enough for signatures
            }
        }

        // Heuristic check (only for PHP files)
        $ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
        if ( $ext === 'php' ) {
            foreach ( self::$heuristic_patterns as $pattern => $desc ) {
                if ( @preg_match( $pattern, $content ) ) {
                    $results['threats'][] = array(
                        'type'        => 'heuristic',
                        'severity'    => 'warning',
                        'location'    => $rel,
                        'description' => 'Suspicious pattern: ' . $desc,
                        'file'        => $path,
                    );
                    break; // One heuristic hit per file
                }
            }
        }
    }

    private static function scan_fake_jpgs( &$results ) {
        $upload_dir = WP_CONTENT_DIR . '/uploads/';
        for ( $i = 0; $i <= 5; $i++ ) {
            $ts  = strtotime( '-' . $i . ' months' );
            $dir = $upload_dir . date( 'Y', $ts ) . '/' . date( 'm', $ts ) . '/';
            if ( ! is_dir( $dir ) ) continue;
            $files = glob( $dir . 'gallery-thumb-????????.jpg' );
            if ( ! $files ) continue;
            foreach ( $files as $file ) {
                $bytes = @file_get_contents( $file, false, null, 0, 200 );
                if ( ! $bytes ) continue;
                if ( substr( $bytes, 0, 4 ) !== "\xFF\xD8\xFF\xE0" ) continue;
                $fc = @file_get_contents( $file );
                if ( $fc && preg_match( '/\d{10}\|[\d\.]+\|https?:\/\//', $fc ) ) {
                    $results['threats'][] = array(
                        'type'        => 'credential_log',
                        'severity'    => 'critical',
                        'location'    => str_replace( ABSPATH, '', $file ),
                        'description' => 'Fake JPEG credential log file — contains harvested login data',
                        'file'        => $file,
                    );
                }
            }
        }
    }

    // ── Database scanning ─────────────────────────────────────────────

    private static function scan_database( &$results ) {
        global $wpdb;

        // Known option key patterns
        foreach ( self::$db_signatures as $pattern ) {
            $rows = $wpdb->get_results( $wpdb->prepare(
                "SELECT option_name, LENGTH(option_value) AS vlen FROM {$wpdb->options} WHERE option_name LIKE %s",
                $pattern
            ) );
            foreach ( $rows as $row ) {
                $results['db_rows_scanned']++;
                $results['threats'][] = array(
                    'type'        => 'database',
                    'severity'    => 'critical',
                    'location'    => 'wp_options: ' . $row->option_name,
                    'description' => 'Known malware option key (' . number_format( $row->vlen ) . ' bytes)',
                    'option_name' => $row->option_name,
                );
            }
        }

        // PHP payload blobs (base64-encoded PHP starting with <?php)
        $blobs = $wpdb->get_results(
            "SELECT option_name, LENGTH(option_value) AS vlen FROM {$wpdb->options}
             WHERE LENGTH(option_value) > 5000 AND option_value LIKE 'PD9waH%'"
        );
        foreach ( $blobs as $row ) {
            $results['db_rows_scanned']++;
            $results['threats'][] = array(
                'type'        => 'database',
                'severity'    => 'critical',
                'location'    => 'wp_options: ' . $row->option_name,
                'description' => 'PHP payload blob stored in database (' . number_format( $row->vlen ) . ' bytes)',
                'option_name' => $row->option_name,
            );
        }

        // JS payload blobs
        $js_blobs = $wpdb->get_results(
            "SELECT option_name, LENGTH(option_value) AS vlen FROM {$wpdb->options}
             WHERE LENGTH(option_value) > 2000
             AND ( option_value LIKE 'KGZ1bmN0%' OR option_value LIKE 'dmFyIF8%' OR option_value LIKE 'KHZhciB%' )"
        );
        foreach ( $js_blobs as $row ) {
            $safe = array( 'wp_user_roles', 'rewrite_rules', 'widget_', 'sidebars_widgets', 'elementor' );
            $is_safe = false;
            foreach ( $safe as $s ) {
                if ( strpos( $row->option_name, $s ) !== false ) { $is_safe = true; break; }
            }
            if ( ! $is_safe ) {
                $results['db_rows_scanned']++;
                $results['threats'][] = array(
                    'type'        => 'database',
                    'severity'    => 'critical',
                    'location'    => 'wp_options: ' . $row->option_name,
                    'description' => 'Obfuscated JS payload blob in database (' . number_format( $row->vlen ) . ' bytes)',
                    'option_name' => $row->option_name,
                );
            }
        }

        // Extra meta payload rows
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
                $results['db_rows_scanned'] += $count;
                $results['threats'][] = array(
                    'type'        => 'database',
                    'severity'    => 'critical',
                    'location'    => $table . ' (meta table)',
                    'description' => $count . ' malware payload row(s) matching _wpv% pattern',
                );
            }
        }

        // Malware cron jobs
        $known_cron_hooks = array(
            'taxonomy_cache_flush_c30d', 'role_cache_rebuild_0958',
            'site_optimization_scan_76cc',
        );
        foreach ( $known_cron_hooks as $hook ) {
            if ( wp_next_scheduled( $hook ) ) {
                $results['threats'][] = array(
                    'type'        => 'cron',
                    'severity'    => 'critical',
                    'location'    => 'WP Cron: ' . $hook,
                    'description' => 'Known malware cron job is scheduled',
                    'cron_hook'   => $hook,
                );
            }
        }

        // Hidden admin accounts
        $known_backdoor_users = array( 'siteadmin', 'techsupport', 'wpmanager', 'wpadmin99' );
        foreach ( $known_backdoor_users as $login ) {
            if ( username_exists( $login ) ) {
                $results['threats'][] = array(
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
