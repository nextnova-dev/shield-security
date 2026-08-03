<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Shield Security Scanner — PHP 7.0 compatible, chunked AJAX steps
 * FIX v1.2: Backslash syntax error fixed, own-dir exclusion via helpers,
 *           signatures stored split, fake JPEG scan added as dedicated step.
 */
class Shield_Scanner {

    // Signatures split across concatenation so scanner cannot match its own source.
    // PHP joins them at runtime — the full strings never appear in this file.
    private static function get_file_signatures() {
        return array(
            '_ac_'   . '23da9d25',
            '_ac_'   . '07d0b218',
            '_wpc_'  . '375586e3',
            '_ac_'   . 'ce79ae25',
            'wp_15384834' . 'c4_cfg',
            'Opt_Service' . '_002e',
            // Starter Render Loader / blockchain C2 family
            'webanalytics' . '-cdn.sbs',
            'Cache_Load' . 'er_727f',
            '_192ae' . '6_hb',
            'wp_c9cd' . '735c_tick',
            'polygon' . '.drpc.org',
            'webanalytics' . '-cdn',
            // Smart Database Engine / decoy-scatter family
            'Opt_Module' . '_20d2',
            'wp_2170b6' . 'c732_cfg',
            'gzinflate(@base64' . '_decode',
            // Smart Resource Enhancer family (manifest.bin / 875L header)
            'Query_Help' . 'er_770a',
            'smart-resource-enhancer' . '-7659',
            'manifest' . '.bin',
            '_19274' . '633_LOADED',
            'base64_decode' . '(gzinflate',
            'eval'   . '(base64_decode',
            'eval'   . '(gzinflate',
            'str_rot13' . '(base64',
            'assert' . '(base64',
            'preg_replace' . '("/.*/e"',
            'create_' . 'function(',
            'shell_exec' . '($_',
            'system' . '($_',
            'passthru' . '($_',
            'exec'   . '($_',
        );
    }

    private static function get_db_signatures() {
        return array(
            '_site_health_scan_config%',
            '_site_login_attempt_log%',
            'taxonomy_cache_flush_%',
            '_ac_' . '23da9d25%',
            '_ac_' . '07d0b218%',
            '_wpc_' . '375586e3%',
            '_ac_' . 'ce79ae25%',
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
            'wp_15384834' . 'c4_cfg',
            'role_cache_rebuild_%',
            'site_optimization_scan_%',
            // Starter Render Loader family
            'starter-render-loader-f386%',
            '_192ae6_%',
            // Smart Database Engine / decoy-scatter family
            'wp_2170b6c732%',
            'smart-database-engine%',
            // Smart Resource Enhancer family
            'smart-resource-enhancer-7659%',
        );
    }

    private static function get_heuristic_patterns() {
        return array(
            '/\beval\s*\(\s*base64_decode\s*\(/'             => 'eval+base64_decode (obfuscation)',
            '/\beval\s*\(\s*gzinflate\s*\(/'                 => 'eval+gzinflate (compressed payload)',
            '/\beval\s*\(\s*str_rot13\s*\(/'                  => 'eval+str_rot13 (obfuscation)',
            '/base64_decode\s*\([\'"][A-Za-z0-9+\/]{500,}/'  => 'large inline base64 blob',
            '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+/'   => 'char-by-char string construction',
            '/add_action\s*\(\s*[\'"]wp_footer[\'"].*\d{5,}/' => 'wp_footer very high priority hook',
            '/preg_replace\s*\([\'"]\/.*\/e[\'"]/'           => 'preg_replace /e modifier (RCE)',
            '/String\.fromCharCode\s*\(/'                    => 'JS fromCharCode (obfuscated output)',
        );
    }

    private static $scan_extensions = array( 'php', 'js', 'html', 'htm' );
    private static $skip_dirs       = array( 'node_modules', '.git' );

    // ── Step definitions ─────────────────────────────────────────────
    public static function get_steps() {
        return array(
            'mu_plugins' => 'MU Plugins',
            'plugins'    => 'Plugins Folder',
            'themes'     => 'Active Theme',
            'dropins'    => 'Drop-in Files & wp-login.php',
            'scatter'    => 'RAT Scatter Directories',
            'fake_jpgs'  => 'Fake JPEG Credential Logs',
            'database'   => 'Database (wp_options)',
            'system'     => 'Cron Jobs & Admin Users',
            'finalise'   => 'Finalise & Save Results',
        );
    }

    // ── Partial result transient ─────────────────────────────────────
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
        set_transient( 'shield_scan_partial', $data, 1800 );
    }

    private static function clear_partial() {
        delete_transient( 'shield_scan_partial' );
    }

    // ── Run one step ─────────────────────────────────────────────────
    public static function run_step( $step ) {
        @set_time_limit( 60 );
        $partial = self::get_partial();

        if ( in_array( $step, $partial['steps_done'], true ) ) {
            return array( 'ok' => true, 'step' => $step, 'already_done' => true, 'threats_found' => 0, 'files_scanned' => 0 );
        }

        $threats_before = count( $partial['threats'] );
        $files_before   = $partial['files_scanned'];
        $start          = microtime( true );

        switch ( $step ) {
            case 'mu_plugins': self::scan_directory( WPMU_PLUGIN_DIR, $partial ); break;
            case 'plugins':
                self::scan_directory( WP_PLUGIN_DIR, $partial );
                self::scan_decoy_plugins( $partial );
                break;
            case 'themes':
                self::scan_directory( get_template_directory(), $partial );
                $child = get_stylesheet_directory();
                if ( $child !== get_template_directory() ) self::scan_directory( $child, $partial );
                break;
            case 'dropins':
                foreach ( array(
                    WP_CONTENT_DIR . '/advanced-cache.php',
                    WP_CONTENT_DIR . '/db.php',
                    WP_CONTENT_DIR . '/object-cache.php',
                    ABSPATH . 'wp-login.php',
                ) as $path ) { self::scan_file_if_exists( $path, $partial ); }
                break;
            case 'scatter':
                foreach ( array( 'fonts', 'cache', 'upgrade', 'languages' ) as $dir ) {
                    $path = WP_CONTENT_DIR . '/' . $dir;
                    if ( is_dir( $path ) ) self::scan_directory( $path, $partial, 1 );
                }
                break;
            case 'fake_jpgs':  self::scan_fake_jpgs( $partial );  break;
            case 'database':   self::scan_database( $partial );   break;
            case 'system':     self::scan_system( $partial );     break;
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

    // ── File scanning ────────────────────────────────────────────────
    private static function scan_directory( $dir, &$partial, $max_depth = 10, $depth = 0 ) {
        if ( ! is_dir( $dir ) || $depth > $max_depth ) return;
        // Use helpers function — no manual path string manipulation here
        if ( shield_path_is_excluded( $dir ) ) return;
        $base = basename( $dir );
        foreach ( self::$skip_dirs as $skip ) {
            if ( $base === $skip ) return;
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
        if ( shield_path_is_excluded( $path ) ) return;
        if ( file_exists( $path ) ) self::scan_file( $path, $partial );
    }

    private static function scan_file( $path, &$partial ) {
        if ( shield_path_is_excluded( $path ) ) return;
        $partial['files_scanned']++;
        $content = @file_get_contents( $path );
        if ( $content === false || strlen( $content ) === 0 ) return;
        $rel = str_replace( ABSPATH, '', $path );

        foreach ( self::get_file_signatures() as $sig ) {
            if ( strpos( $content, $sig ) !== false ) {
                $partial['threats'][] = array(
                    'type'        => 'signature',
                    'severity'    => 'critical',
                    'location'    => $rel,
                    'description' => 'Known malware signature detected',
                    'file'        => $path,
                );
                return;
            }
        }

        if ( strtolower( pathinfo( $path, PATHINFO_EXTENSION ) ) === 'php' ) {
            foreach ( self::get_heuristic_patterns() as $pattern => $desc ) {
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

    // ── Decoy / empty plugin file detection + subdirectory plugin structure ─
    // Detects the scatter-decoy technique: folders of single-file plugins
    // where most are empty (0 bytes) to confuse admins, hiding one active
    // malware file among them. Flags the [word]-[word]-[4hex].php pattern.
    private static function scan_decoy_plugins( &$partial ) {
        $name_pattern = '/^[a-z]+(?:-[a-z0-9]+)+-[0-9a-f]{4}\.php$/i';
        $handle = @opendir( WP_PLUGIN_DIR );
        if ( ! $handle ) return;
        while ( ( $item = readdir( $handle ) ) !== false ) {
            if ( $item === '.' || $item === '..' ) continue;
            $plugin_dir = WP_PLUGIN_DIR . '/' . $item;
            if ( ! is_dir( $plugin_dir ) ) continue;
            if ( shield_path_is_excluded( $plugin_dir ) ) continue;
            $php_files = glob( $plugin_dir . '/*.php' );
            if ( ! $php_files ) continue;
            foreach ( $php_files as $file ) {
                $basename = basename( $file );
                if ( ! preg_match( $name_pattern, $basename ) ) continue;
                $size = @filesize( $file );
                $rel  = str_replace( ABSPATH, '', $file );
                if ( $size === 0 ) {
                    $partial['threats'][] = array(
                        'type'        => 'decoy_plugin',
                        'severity'    => 'warning',
                        'location'    => $rel,
                        'description' => 'Empty decoy plugin file — part of scatter confusion technique (hex-suffix naming pattern)',
                        'file'        => $file,
                    );
                    $partial['files_scanned']++;
                } else {
                    self::scan_file( $file, $partial );
                }
            }
        }
        // Also flag any plugin folder containing manifest.bin in a static/ subdir
        // This is the smart-resource-enhancer family structure
        $manifest_dirs = glob( WP_PLUGIN_DIR . '/*/static/manifest.bin' );
        if ( $manifest_dirs ) {
            foreach ( $manifest_dirs as $mfile ) {
                $rel = str_replace( ABSPATH, '', $mfile );
                if ( shield_path_is_excluded( $mfile ) ) continue;
                $partial['threats'][] = array(
                    'type'        => 'signature',
                    'severity'    => 'critical',
                    'location'    => $rel,
                    'description' => 'Encrypted malware payload (manifest.bin) — smart-resource-enhancer family',
                    'file'        => $mfile,
                );
            }
        }
        closedir( $handle );
    }

    // ── Fake JPEG scan ───────────────────────────────────────────────
    private static function scan_fake_jpgs( &$partial ) {
        $upload_dir = WP_CONTENT_DIR . '/uploads/';
        // Scan last 6 months + any year/month folder in uploads
        $dirs_to_check = array();
        for ( $i = 0; $i <= 11; $i++ ) {
            $ts  = strtotime( '-' . $i . ' months' );
            $dirs_to_check[] = $upload_dir . date( 'Y', $ts ) . '/' . date( 'm', $ts ) . '/';
        }
        // Also do a broader glob across all year folders
        $year_dirs = glob( $upload_dir . '[0-9][0-9][0-9][0-9]/', GLOB_ONLYDIR );
        if ( $year_dirs ) {
            foreach ( $year_dirs as $year_dir ) {
                $month_dirs = glob( $year_dir . '[0-9][0-9]/', GLOB_ONLYDIR );
                if ( $month_dirs ) {
                    foreach ( $month_dirs as $md ) $dirs_to_check[] = $md;
                }
            }
        }
        $dirs_to_check = array_unique( $dirs_to_check );
        $found = 0;
        foreach ( $dirs_to_check as $dir ) {
            if ( ! is_dir( $dir ) ) continue;
            // Pattern: gallery-thumb-XXXXXXXX.jpg (8 hex chars)
            $files = glob( $dir . 'gallery-thumb-????????.jpg' );
            if ( ! $files ) continue;
            foreach ( $files as $file ) {
                // Read first 4 bytes to check JPEG magic bytes
                $bytes = @file_get_contents( $file, false, null, 0, 4 );
                if ( $bytes === false ) continue;
                // Real JPEGs start with FF D8 FF
                if ( substr( $bytes, 0, 3 ) !== "\xFF\xD8\xFF" ) continue;
                // Read full file and look for credential pattern: timestamp|ip|url
                $fc = @file_get_contents( $file );
                // Check for old format: timestamp|ip|url
                $is_cred_log = $fc && preg_match( '/\d{10}\|[\d\.]+\|https?:\/\//', $fc );
                // Check for new format: base64 lines after JFIF header (smart-resource-enhancer family)
                if ( ! $is_cred_log && $fc ) {
                    $after_jfif = substr( $fc, 20 );
                    $is_cred_log = (bool) preg_match( '/^[A-Za-z0-9+\/]{80,}={0,2}$/m', $after_jfif );
                }
                if ( $is_cred_log ) {
                    $rel = str_replace( ABSPATH, '', $file );
                    $partial['threats'][] = array(
                        'type'        => 'fake_jpg',
                        'severity'    => 'critical',
                        'location'    => $rel,
                        'description' => 'Fake JPEG credential log — contains harvested login data',
                        'file'        => $file,
                    );
                    $found++;
                }
            }
        }
        if ( $found === 0 ) {
            // No threats, but record that we scanned (add a note to partial)
            $partial['fake_jpg_scanned'] = true;
        }
    }

    // ── Database scanning ────────────────────────────────────────────
    private static function scan_database( &$partial ) {
        global $wpdb;

        foreach ( self::get_db_signatures() as $pattern ) {
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

        // PHP payload blobs (base64 <?php)
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

        // Meta table payloads
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

    // ── System scanning ──────────────────────────────────────────────
    private static function scan_system( &$partial ) {
        $known_hooks = array(
            'taxonomy_cache_flush_c30d',   // media-indexer RAT
            'role_cache_rebuild_0958',     // object-cache-bridge RAT
            'site_optimization_scan_76cc', // wp-session-handler RAT
            'wp_c9cd735c_tick',            // Starter Render Loader / blockchain C2
        );
        foreach ( $known_hooks as $hook ) {
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
        $known_users = array( 'siteadmin', 'techsupport', 'wpmanager', 'wpadmin99' );
        foreach ( $known_users as $login ) {
            if ( username_exists( $login ) ) {
                $partial['threats'][] = array(
                    'type'        => 'user',
                    'severity'    => 'critical',
                    'location'    => 'wp_users: ' . $login,
                    'description' => 'Known backdoor admin account: ' . $login,
                    'username'    => $login,
                );
            }
        }
    }

    private static function finalise( &$partial ) {
        $results = array(
            'started_at'      => $partial['started_at'],
            'completed_at'    => current_time( 'mysql' ),
            'threats'         => $partial['threats'],
            'files_scanned'   => $partial['files_scanned'],
            'db_rows_scanned' => $partial['db_rows_scanned'],
            'threat_count'    => count( $partial['threats'] ),
        );
        update_option( 'shield_last_scan', $results );
        $count = $results['threat_count'];
        shield_log( 'Scan complete. ' . $count . ' threat(s) found.', $count > 0 ? 'warn' : 'info' );
        if ( $count > 0 ) {
            $body = "Shield Security detected {$count} threat(s) on " . home_url() . ".\n\n";
            foreach ( $results['threats'] as $t ) {
                $body .= '- [' . $t['type'] . '] ' . $t['location'] . ': ' . $t['description'] . "\n";
            }
            shield_send_alert( $count . ' threat(s) detected', $body );
        }
    }

    public static function get_last_scan() {
        return get_option( 'shield_last_scan', null );
    }

    // Backwards-compat full scan
    public static function run_scan() {
        self::clear_partial();
        foreach ( array_keys( self::get_steps() ) as $step ) self::run_step( $step );
        return get_option( 'shield_last_scan', array() );
    }
}
