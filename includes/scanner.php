<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Shield Security Scanner v1.3.1
 * PHP 7.0 compatible — chunked AJAX steps — all known variants included
 */
class Shield_Scanner {

    // Signatures split so scanner cannot self-match
    private static function get_file_signatures() {
        return array(
            // RAT family v1-v4
            '_ac_'   . '23da9d25', '_ac_' . '07d0b218',
            '_wpc_'  . '375586e3', '_ac_' . 'ce79ae25',
            // JS injector / blockchain C2
            'wp_15384834' . 'c4_cfg', 'Opt_Service' . '_002e',
            'webanalytics' . '-cdn.sbs', 'Cache_Load' . 'er_727f',
            '_192ae' . '6_hb', 'wp_c9cd' . '735c_tick',
            'polygon' . '.drpc.org',
            // Smart DB Engine / decoy-scatter
            'Opt_Module' . '_20d2', 'wp_2170b6' . 'c732_cfg',
            'gzinflate(@base64' . '_decode',
            // Smart Resource Enhancer / manifest.bin
            'Query_Help' . 'er_770a', '_19274' . '633_LOADED',
            // Advanced Health Scanner / Auto Cache Engine / Total Content Enhancer
            'advanced-health-scanner' . '-a415',
            'auto-cache-engine' . '-7393',
            'total-content-enhancer' . '-582b',
            'Opt_Engine' . '_b291',   // generic class name pattern
            // Known payload file names (found in plugin subdirs)
            'resources/config' . '.dat',
            'static/metadata' . '.cache',
            'cache/config' . '.dat',
            // Common malware patterns
            'base64_decode' . '(gzinflate', 'eval' . '(base64_decode',
            'eval' . '(gzinflate', 'str_rot13' . '(base64',
            'assert' . '(base64', 'preg_replace' . '("/.*/e"',
            'create_' . 'function(',
            'shell_exec' . '($_', 'system' . '($_',
            'passthru' . '($_', 'exec' . '($_',
        );
    }

    private static function get_db_signatures() {
        return array(
            // RAT family
            '_site_health_scan_config%', '_site_login_attempt_log%',
            'taxonomy_cache_flush_%',
            '_ac_' . '23da9d25%', '_ac_' . '07d0b218%',
            '_wpc_' . '375586e3%', '_ac_' . 'ce79ae25%',
            '_core_version_check_hash%', '_site_auth_tokens_hash%',
            '_wph_5945%', '_wpc_f4bd6e7c%',
            '_wp_rewrite_rules_cache%', '_wp_login_session_data%',
            '_wp_core_settings_cache%', '_wpc_0b8206e3%',
            '_wph_2e29%', '_wpv%',
            '_core_integrity_hash%', '_wp_auth_cookie_cache%',
            '_site_compatibility_data%', 'role_cache_rebuild_%',
            'site_optimization_scan_%',
            // JS injector / blockchain
            'wp_15384834' . 'c4_cfg',
            'starter-render-loader-f386%', '_192ae6_%',
            // Decoy-scatter
            'wp_2170b6c732%', 'smart-database-engine%',
            // Smart Resource Enhancer
            'smart-resource-enhancer-7659%',
            // New variants (nextnovadev)
            'advanced-health-scanner-a415%',
            // Uploads webshell restore mechanism
            '_wp_cron_lock_status',
            '_wp_cron_lock%',
            'role-cache%',
            'wp_cache_stats%',
            'auto-cache-engine-7393%',
            'total-content-enhancer-582b%',
        );
    }

    private static function get_heuristic_patterns() {
        return array(
            '/\beval\s*\(\s*base64_decode\s*\(/'             => 'eval+base64_decode',
            '/\beval\s*\(\s*gzinflate\s*\(/'                 => 'eval+gzinflate',
            '/base64_decode\s*\([\'"][A-Za-z0-9+\/]{500,}/'  => 'large base64 blob',
            '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+/'   => 'char-by-char string',
            '/add_action\s*\(\s*[\'"]wp_footer[\'"].*\d{5,}/' => 'high-priority wp_footer hook',
            '/preg_replace\s*\([\'"]\/.*\/e[\'"]/'           => 'preg_replace /e (RCE)',
            '/String\.fromCharCode\s*\(/'                    => 'JS fromCharCode',
            '/gzinflate\s*\(\s*@?base64_decode/'             => 'gzinflate+base64',
        );
    }

    // Known payload binary file patterns (found in plugin subdirectories)
    private static function get_payload_file_patterns() {
        return array(
            '*/resources/config.dat',
            '*/resources/index.idx',
            '*/static/metadata.cache',
            '*/static/data.cache',
            '*/static/manifest.bin',
            '*/cache/config.dat',
            '*/cache/index.cache',
            '*/core/config.dat',
        );
    }

    private static $scan_extensions = array( 'php', 'js', 'html', 'htm' );
    private static $skip_dirs       = array( 'node_modules', '.git' );

    public static function get_steps() {
        return array(
            'mu_plugins'  => 'MU Plugins',
            'plugins'     => 'Plugins Folder',
            'themes'      => 'Active Theme',
            'dropins'     => 'Drop-in Files & wp-login.php',
            'scatter'     => 'RAT Scatter Directories',
            'fake_jpgs'   => 'Fake JPEG Credential Logs',
            'payload_bins'=> 'Binary Payload Files (new variants)',
            'uploads_php' => 'PHP Files in Uploads (webshells)',
            'database'    => 'Database (wp_options)',
            'system'      => 'Cron Jobs & Admin Users',
            'finalise'    => 'Finalise & Save Results',
        );
    }

    // ── Partial transient ─────────────────────────────────────────────
    private static function get_partial() {
        $data = get_transient( 'shield_scan_partial' );
        if ( ! is_array( $data ) ) {
            $data = array(
                'started_at' => current_time( 'mysql' ),
                'threats'    => array(),
                'files_scanned'   => 0,
                'db_rows_scanned' => 0,
                'steps_done'      => array(),
            );
        }
        return $data;
    }
    private static function save_partial( $data ) { set_transient( 'shield_scan_partial', $data, 1800 ); }
    private static function clear_partial() { delete_transient( 'shield_scan_partial' ); }

    // ── Run one step ──────────────────────────────────────────────────
    public static function run_step( $step ) {
        @set_time_limit( 60 );
        $partial = self::get_partial();
        if ( in_array( $step, $partial['steps_done'], true ) ) {
            return array( 'ok' => true, 'step' => $step, 'already_done' => true, 'threats_found' => 0, 'files_scanned' => 0 );
        }
        $t_before = count( $partial['threats'] );
        $f_before = $partial['files_scanned'];
        $start    = microtime( true );

        switch ( $step ) {
            case 'mu_plugins':   self::scan_directory( WPMU_PLUGIN_DIR, $partial ); break;
            case 'plugins':
                self::scan_directory( WP_PLUGIN_DIR, $partial );
                self::scan_decoy_plugins( $partial );
                break;
            case 'themes':
                self::scan_directory( get_template_directory(), $partial );
                $c = get_stylesheet_directory();
                if ( $c !== get_template_directory() ) self::scan_directory( $c, $partial );
                break;
            case 'dropins':
                foreach ( array(
                    WP_CONTENT_DIR . '/advanced-cache.php',
                    WP_CONTENT_DIR . '/db.php',
                    WP_CONTENT_DIR . '/object-cache.php',
                    ABSPATH . 'wp-login.php',
                ) as $p ) { self::scan_file_if_exists( $p, $partial ); }
                break;
            case 'scatter':
                foreach ( array( 'fonts', 'cache', 'upgrade', 'languages' ) as $d ) {
                    $p = WP_CONTENT_DIR . '/' . $d;
                    if ( is_dir( $p ) ) self::scan_directory( $p, $partial, 1 );
                }
                break;
            case 'fake_jpgs':    self::scan_fake_jpgs( $partial );     break;
            case 'uploads_php':  self::scan_uploads_php( $partial );    break;
            case 'payload_bins': self::scan_payload_binaries( $partial ); break;
            case 'database':     self::scan_database( $partial );      break;
            case 'system':       self::scan_system( $partial );        break;
            case 'finalise':
                self::finalise( $partial );
                self::clear_partial();
                return array(
                    'ok' => true, 'step' => $step, 'final' => true,
                    'threat_count'  => count( $partial['threats'] ),
                    'threats_found' => count( $partial['threats'] ) - $t_before,
                    'files_scanned' => $partial['files_scanned'] - $f_before,
                    'time'          => round( microtime( true ) - $start, 2 ),
                );
        }
        $partial['steps_done'][] = $step;
        self::save_partial( $partial );
        return array(
            'ok'            => true,
            'step'          => $step,
            'threats_found' => count( $partial['threats'] ) - $t_before,
            'files_scanned' => $partial['files_scanned'] - $f_before,
            'total_threats' => count( $partial['threats'] ),
            'time'          => round( microtime( true ) - $start, 2 ),
        );
    }

    // ── File scanning ─────────────────────────────────────────────────
    private static function scan_directory( $dir, &$partial, $max_depth = 10, $depth = 0 ) {
        if ( ! is_dir( $dir ) || $depth > $max_depth ) return;
        if ( shield_path_is_excluded( $dir ) ) return;
        $base = basename( $dir );
        foreach ( self::$skip_dirs as $skip ) { if ( $base === $skip ) return; }
        $handle = @opendir( $dir );
        if ( ! $handle ) return;
        while ( ( $item = readdir( $handle ) ) !== false ) {
            if ( $item === '.' || $item === '..' ) continue;
            $path = $dir . '/' . $item;
            if ( is_dir( $path ) ) {
                self::scan_directory( $path, $partial, $max_depth, $depth + 1 );
            } elseif ( is_file( $path ) ) {
                $ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
                if ( in_array( $ext, self::$scan_extensions, true ) ) self::scan_file( $path, $partial );
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
                    'type' => 'signature', 'severity' => 'critical',
                    'location' => $rel, 'file' => $path,
                    'description' => 'Known malware signature detected',
                );
                return;
            }
        }
        if ( strtolower( pathinfo( $path, PATHINFO_EXTENSION ) ) === 'php' ) {
            foreach ( self::get_heuristic_patterns() as $pattern => $desc ) {
                if ( @preg_match( $pattern, $content ) ) {
                    $partial['threats'][] = array(
                        'type' => 'heuristic', 'severity' => 'warning',
                        'location' => $rel, 'file' => $path,
                        'description' => 'Suspicious pattern: ' . $desc,
                    );
                    break;
                }
            }
        }
    }

    // ── Decoy plugin detection ────────────────────────────────────────
    private static function scan_decoy_plugins( &$partial ) {
        // Pattern 1: [word]-[word]-[word]-[4hex].php (JS injector family)
        $hex4_pattern = '/^[a-z]+(?:-[a-z0-9]+)+-[0-9a-f]{4}\.php$/i';
        // Pattern 2: wp-[word]-[word]-[unix_timestamp].php (new timestamp variant)
        $ts_pattern   = '/^wp-[a-z]+-[a-z]+-\d{9,10}\.php$/i';

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
                if ( ! preg_match( $hex4_pattern, $basename ) ) continue;
                $size = @filesize( $file );
                $rel  = str_replace( ABSPATH, '', $file );
                $type = ( $size === 0 ) ? 'decoy_plugin' : 'signature';
                $desc = ( $size === 0 )
                    ? 'Empty decoy plugin file (hex-suffix pattern) — scatter confusion technique'
                    : 'Rogue plugin file (hex-suffix naming pattern)';
                $sev  = ( $size === 0 ) ? 'warning' : 'critical';
                $partial['threats'][] = array( 'type' => $type, 'severity' => $sev, 'location' => $rel, 'file' => $file, 'description' => $desc );
                $partial['files_scanned']++;
            }
        }
        closedir( $handle );

        // Also scan mu-plugins for timestamp-suffix decoys
        $mu_handle = @opendir( WPMU_PLUGIN_DIR );
        if ( ! $mu_handle ) return;
        while ( ( $item = readdir( $mu_handle ) ) !== false ) {
            if ( $item === '.' || $item === '..' ) continue;
            $path = WPMU_PLUGIN_DIR . '/' . $item;
            if ( ! is_file( $path ) || pathinfo( $path, PATHINFO_EXTENSION ) !== 'php' ) continue;
            if ( shield_path_is_excluded( $path ) ) continue;
            if ( preg_match( $ts_pattern, $item ) ) {
                $size = @filesize( $path );
                $rel  = str_replace( ABSPATH, '', $path );
                $partial['threats'][] = array(
                    'type'        => $size === 0 ? 'decoy_plugin' : 'signature',
                    'severity'    => $size === 0 ? 'warning' : 'critical',
                    'location'    => $rel,
                    'file'        => $path,
                    'description' => 'Suspicious MU-plugin: timestamp-suffix naming (wp-*-*-[timestamp].php) — known decoy pattern',
                );
                $partial['files_scanned']++;
            }
        }
        closedir( $mu_handle );

        // Scan for binary payload files across all plugin subdirectories
        self::scan_payload_bins_in_plugins( $partial );
    }

    // ── Binary payload file detection (config.dat, metadata.cache etc) ─
    private static function scan_payload_binaries( &$partial ) {
        // Already called during plugins step — this step does a broader sweep
        $search_dirs = array( WP_CONTENT_DIR . '/uploads', WP_CONTENT_DIR );
        foreach ( $search_dirs as $dir ) {
            if ( ! is_dir( $dir ) ) continue;
            $patterns = array( '*.dat', '*.idx', '*.bin' );
            foreach ( $patterns as $pat ) {
                $found = glob( $dir . '/' . $pat );
                if ( $found ) {
                    foreach ( $found as $file ) {
                        if ( shield_path_is_excluded( $file ) ) continue;
                        $size = @filesize( $file );
                        if ( $size > 1000 && $size < 50000 ) {
                            $bytes = @file_get_contents( $file, false, null, 0, 4 );
                            // Known malware magic bytes
                            $known_magic = array( 'VE6T', '875L', 'TGHV', 'TXQH', 'R9ZL' );
                            if ( $bytes && in_array( $bytes, $known_magic, true ) ) {
                                $rel = str_replace( ABSPATH, '', $file );
                                $partial['threats'][] = array(
                                    'type' => 'payload_binary', 'severity' => 'critical',
                                    'location' => $rel, 'file' => $file,
                                    'description' => 'Known encrypted malware payload (magic: ' . $bytes . ')',
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    private static function scan_payload_bins_in_plugins( &$partial ) {
        $known_magic = array( 'VE6T', '875L', 'TGHV', 'TXQH', 'R9ZL' );
        $payload_names = array( 'config.dat', 'metadata.cache', 'index.idx', 'data.cache', 'index.cache', 'manifest.bin', 'manifest.cache' );
        $subdirs = array( 'resources', 'static', 'cache', 'lib', 'includes', 'inc', 'core', 'data' );

        $handle = @opendir( WP_PLUGIN_DIR );
        if ( ! $handle ) return;
        while ( ( $item = readdir( $handle ) ) !== false ) {
            if ( $item === '.' || $item === '..' ) continue;
            $plugin_dir = WP_PLUGIN_DIR . '/' . $item;
            if ( ! is_dir( $plugin_dir ) || shield_path_is_excluded( $plugin_dir ) ) continue;
            foreach ( $subdirs as $sub ) {
                $subdir = $plugin_dir . '/' . $sub;
                if ( ! is_dir( $subdir ) ) continue;
                foreach ( $payload_names as $pname ) {
                    $pfile = $subdir . '/' . $pname;
                    if ( ! file_exists( $pfile ) ) continue;
                    $size = @filesize( $pfile );
                    if ( $size < 500 || $size > 100000 ) continue;
                    $bytes = @file_get_contents( $pfile, false, null, 0, 4 );
                    // Flag if: known magic OR high entropy suspected (all binary payloads)
                    if ( $bytes && in_array( $bytes, $known_magic, true ) ) {
                        $rel = str_replace( ABSPATH, '', $pfile );
                        $partial['threats'][] = array(
                            'type' => 'payload_binary', 'severity' => 'critical',
                            'location' => $rel, 'file' => $pfile,
                            'description' => 'Known encrypted malware payload in plugin subdir (magic: ' . $bytes . ')',
                        );
                    } elseif ( $bytes && ! ctype_print( $bytes ) ) {
                        // Binary file in plugin subdir with no known magic — still suspicious
                        $rel = str_replace( ABSPATH, '', $pfile );
                        $partial['threats'][] = array(
                            'type' => 'payload_binary', 'severity' => 'warning',
                            'location' => $rel, 'file' => $pfile,
                            'description' => 'Suspicious binary file in plugin subdir — possible encrypted payload (new variant)',
                        );
                    }
                }
            }
        }
        closedir( $handle );
    }

    // ── Fake JPEG scan ────────────────────────────────────────────────
    private static function scan_fake_jpgs( &$partial ) {
        $upload_dir = WP_CONTENT_DIR . '/uploads/';
        for ( $i = 0; $i <= 11; $i++ ) {
            $ts  = strtotime( '-' . $i . ' months' );
            $dir = $upload_dir . date( 'Y', $ts ) . '/' . date( 'm', $ts ) . '/';
            if ( ! is_dir( $dir ) ) continue;
            $files = glob( $dir . 'gallery-thumb-????????.jpg' );
            if ( ! $files ) continue;
            foreach ( $files as $file ) {
                $bytes = @file_get_contents( $file, false, null, 0, 4 );
                if ( ! $bytes || substr( $bytes, 0, 3 ) !== "\xFF\xD8\xFF" ) continue;
                $fc = @file_get_contents( $file );
                if ( ! $fc ) continue;
                // Old format: timestamp|ip|url
                $is_cred = (bool) preg_match( '/\d{10}\|[\d\.]+\|https?:\/\//', $fc );
                // New format: base64 lines after JFIF header
                if ( ! $is_cred ) {
                    $after = substr( $fc, 20 );
                    $is_cred = (bool) preg_match( '/^[A-Za-z0-9+\/]{80,}={0,2}$/m', $after );
                }
                if ( $is_cred ) {
                    $partial['threats'][] = array(
                        'type' => 'fake_jpg', 'severity' => 'critical',
                        'location' => str_replace( ABSPATH, '', $file ),
                        'file' => $file,
                        'description' => 'Fake JPEG credential log — contains harvested login data',
                    );
                }
            }
        }
    }

    // ── Database scan ─────────────────────────────────────────────────
    private static function scan_database( &$partial ) {
        global $wpdb;
        foreach ( self::get_db_signatures() as $pat ) {
            $rows = $wpdb->get_results( $wpdb->prepare( "SELECT option_name, LENGTH(option_value) AS vlen FROM {$wpdb->options} WHERE option_name LIKE %s", $pat ) );
            foreach ( $rows as $r ) {
                $partial['db_rows_scanned']++;
                $partial['threats'][] = array( 'type' => 'database', 'severity' => 'critical', 'location' => 'wp_options: ' . $r->option_name, 'description' => 'Known malware option key (' . number_format( $r->vlen ) . ' bytes)', 'option_name' => $r->option_name );
            }
        }
        // PHP payload blobs
        $blobs = $wpdb->get_results( "SELECT option_name, LENGTH(option_value) AS vlen FROM {$wpdb->options} WHERE LENGTH(option_value) > 5000 AND option_value LIKE 'PD9waH%'" );
        foreach ( $blobs as $r ) { $partial['db_rows_scanned']++; $partial['threats'][] = array( 'type' => 'database', 'severity' => 'critical', 'location' => 'wp_options: ' . $r->option_name, 'description' => 'PHP payload blob (' . number_format( $r->vlen ) . ' bytes)', 'option_name' => $r->option_name ); }
        // JS blobs
        $js = $wpdb->get_results( "SELECT option_name, LENGTH(option_value) AS vlen FROM {$wpdb->options} WHERE LENGTH(option_value) > 2000 AND ( option_value LIKE 'KGZ1bmN0%' OR option_value LIKE 'dmFyIF8%' OR option_value LIKE 'KHZhciB%' )" );
        $safe = array( 'wp_user_roles', 'rewrite_rules', 'widget_', 'sidebars_widgets', 'elementor' );
        foreach ( $js as $r ) {
            $skip = false;
            foreach ( $safe as $s ) { if ( strpos( $r->option_name, $s ) !== false ) { $skip = true; break; } }
            if ( ! $skip ) { $partial['db_rows_scanned']++; $partial['threats'][] = array( 'type' => 'database', 'severity' => 'critical', 'location' => 'wp_options: ' . $r->option_name, 'description' => 'Obfuscated JS payload blob (' . number_format( $r->vlen ) . ' bytes)', 'option_name' => $r->option_name ); }
        }
        // Meta tables
        foreach ( array( $wpdb->postmeta => 'meta_id', $wpdb->usermeta => 'umeta_id', $wpdb->termmeta => 'meta_id', $wpdb->commentmeta => 'meta_id' ) as $table => $pk ) {
            $count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE meta_key LIKE %s AND LENGTH(meta_value) > 500", '_wpv%' ) );
            if ( $count > 0 ) { $partial['db_rows_scanned'] += $count; $partial['threats'][] = array( 'type' => 'database', 'severity' => 'critical', 'location' => $table, 'description' => $count . ' malware payload row(s) matching _wpv%' ); }
        }
    }

    // ── System scan ───────────────────────────────────────────────────
    private static function scan_system( &$partial ) {
        $hooks = array( 'taxonomy_cache_flush_c30d', 'role_cache_rebuild_0958', 'site_optimization_scan_76cc', 'wp_c9cd' . '735c_tick' );
        foreach ( $hooks as $hook ) {
            if ( wp_next_scheduled( $hook ) ) {
                $partial['threats'][] = array( 'type' => 'cron', 'severity' => 'critical', 'location' => 'WP Cron: ' . $hook, 'description' => 'Known malware cron job scheduled', 'cron_hook' => $hook );
            }
        }
        $known_users = array( 'siteadmin', 'techsupport', 'wpmanager', 'wpadmin99' );
        foreach ( $known_users as $login ) {
            if ( username_exists( $login ) ) {
                $partial['threats'][] = array( 'type' => 'user', 'severity' => 'critical', 'location' => 'wp_users: ' . $login, 'description' => 'Known backdoor admin: ' . $login, 'username' => $login );
            }
        }
    }

    // ── PHP files in uploads (webshells) ─────────────────────────────
    // NO legitimate WordPress plugin or theme ever puts PHP in wp-content/uploads.
    // Any .php file there is malware — scan them all.
    private static function scan_uploads_php( &$partial ) {
        $upload_dir = WP_CONTENT_DIR . '/uploads/';
        if ( ! is_dir( $upload_dir ) ) return;

        // Recursive scan for .php files anywhere in uploads
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( $upload_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ( $iterator as $file ) {
            if ( ! $file->isFile() ) continue;
            $path = $file->getPathname();
            $ext  = strtolower( $file->getExtension() );
            if ( $ext !== 'php' ) continue;
            if ( shield_path_is_excluded( $path ) ) continue;

            $partial['files_scanned']++;
            $rel     = str_replace( ABSPATH, '', $path );
            $size    = $file->getSize();
            $content = $size > 0 ? @file_get_contents( $path ) : '';

            // Always flag PHP in uploads — it is never legitimate
            $desc = 'PHP file in uploads directory — never legitimate, likely webshell';

            // Check for specific dangerous capabilities
            $capabilities = array();
            if ( $content && strpos( $content, 'wp_set_auth_cookie' ) !== false )
                $capabilities[] = 'passwordless admin login';
            if ( $content && strpos( $content, '_wp_cron_lock_status' ) !== false )
                $capabilities[] = 'reads restore payload from DB';
            if ( $content && strpos( $content, 'file_put_contents' ) !== false )
                $capabilities[] = 'writes files to disk';
            if ( $content && strpos( $content, 'shell_exec' ) !== false || ( $content && strpos( $content, 'system(' ) !== false ) )
                $capabilities[] = 'shell execution';
            if ( $content && strpos( $content, 'mu-plugins' ) !== false )
                $capabilities[] = 'targets mu-plugins directory';

            if ( ! empty( $capabilities ) ) {
                $desc = 'Webshell in uploads: ' . implode( ', ', $capabilities );
            }

            $severity = ( ! empty( $capabilities ) || $size > 100 ) ? 'critical' : 'warning';

            $partial['threats'][] = array(
                'type'        => 'webshell',
                'severity'    => $severity,
                'location'    => $rel,
                'file'        => $path,
                'description' => $desc,
            );
        }
    }

    private static function finalise( &$partial ) {
        $results = array(
            'started_at' => $partial['started_at'], 'completed_at' => current_time( 'mysql' ),
            'threats' => $partial['threats'], 'files_scanned' => $partial['files_scanned'],
            'db_rows_scanned' => $partial['db_rows_scanned'], 'threat_count' => count( $partial['threats'] ),
        );
        update_option( 'shield_last_scan', $results );
        $count = $results['threat_count'];
        shield_log( 'Scan complete. ' . $count . ' threat(s) found.', $count > 0 ? 'warn' : 'info' );
        if ( $count > 0 ) {
            $body = "Shield Security detected {$count} threat(s) on " . home_url() . ".\n\n";
            foreach ( $results['threats'] as $t ) $body .= '- [' . $t['type'] . '] ' . $t['location'] . ': ' . $t['description'] . "\n";
            shield_send_alert( $count . ' threat(s) detected', $body );
        }
    }

    public static function get_last_scan() { return get_option( 'shield_last_scan', null ); }
    public static function run_scan() { self::clear_partial(); foreach ( array_keys( self::get_steps() ) as $s ) self::run_step( $s ); return get_option( 'shield_last_scan', array() ); }
}
