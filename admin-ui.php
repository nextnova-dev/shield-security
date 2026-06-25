<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Admin UI — PHP 7.0 compatible
 * Dashboard, Scanner, Settings, License pages
 */
class Shield_Admin_UI {

    public static function init() {
        add_action( 'admin_menu',     array( __CLASS__, 'register_menu' ) );
        add_action( 'admin_head',     array( __CLASS__, 'styles' ) );
        add_action( 'admin_init',     array( __CLASS__, 'handle_actions' ) );
        add_action( 'wp_ajax_shield_run_scan', array( __CLASS__, 'ajax_run_scan' ) );
        add_action( 'wp_ajax_shield_dismiss_threat', array( __CLASS__, 'ajax_dismiss_threat' ) );
        add_action( 'admin_notices',  array( __CLASS__, 'update_notice' ) );
    }

    public static function register_menu() {
        add_menu_page(
            'Shield Security', '🛡 Shield', 'manage_options',
            'shield-security', array( __CLASS__, 'page_dashboard' ),
            'dashicons-shield-alt', 80
        );
        add_submenu_page( 'shield-security', 'Dashboard',      'Dashboard',      'manage_options', 'shield-security',  array( __CLASS__, 'page_dashboard' ) );
        add_submenu_page( 'shield-security', 'Scanner',        'Scanner',        'manage_options', 'shield-scanner',   array( __CLASS__, 'page_scanner' ) );
        add_submenu_page( 'shield-security', 'Login Security', 'Login Security', 'manage_options', 'shield-login',     array( __CLASS__, 'page_login' ) );
        add_submenu_page( 'shield-security', 'Settings',       'Settings',       'manage_options', 'shield-settings',  array( __CLASS__, 'page_settings' ) );
        add_submenu_page( 'shield-security', 'License',        'License',        'manage_options', 'shield-license',   array( __CLASS__, 'page_license' ) );
    }

    public static function handle_actions() {
        if ( ! isset( $_POST['shield_action'] ) ) return;
        shield_admin_only();
        if ( ! shield_verify_nonce() ) wp_die( 'Bad nonce' );

        $action = sanitize_key( $_POST['shield_action'] );

        if ( $action === 'run_scan' ) {
            $results = Shield_Scanner::run_scan();
            $count   = $results['threat_count'];
            wp_redirect( add_query_arg( array( 'page' => 'shield-scanner', 'scanned' => 1, 'threats' => $count ), admin_url( 'admin.php' ) ) );
            exit;
        }

        if ( $action === 'clean_threat' ) {
            $scan    = Shield_Scanner::get_last_scan();
            $idx     = intval( $_POST['threat_index'] ?? -1 );
            if ( $scan && isset( $scan['threats'][ $idx ] ) ) {
                $result = Shield_Cleanup::remove_threat( $scan['threats'][ $idx ] );
                // Remove from saved scan
                array_splice( $scan['threats'], $idx, 1 );
                $scan['threat_count'] = count( $scan['threats'] );
                update_option( 'shield_last_scan', $scan );
                $msg = $result['ok'] ? 'cleaned' : 'error';
            } else {
                $msg = 'notfound';
            }
            wp_redirect( add_query_arg( array( 'page' => 'shield-scanner', 'clean' => $msg ), admin_url( 'admin.php' ) ) );
            exit;
        }

        if ( $action === 'clean_all' ) {
            $scan = Shield_Scanner::get_last_scan();
            if ( $scan && ! empty( $scan['threats'] ) ) {
                Shield_Cleanup::remove_all( $scan['threats'] );
                $scan['threats']     = array();
                $scan['threat_count']= 0;
                update_option( 'shield_last_scan', $scan );
            }
            wp_redirect( add_query_arg( array( 'page' => 'shield-scanner', 'clean' => 'all_done' ), admin_url( 'admin.php' ) ) );
            exit;
        }
    }

    public static function ajax_run_scan() {
        shield_admin_only();
        check_ajax_referer( 'shield_ajax', 'nonce' );
        $results = Shield_Scanner::run_scan();
        wp_send_json_success( array(
            'threat_count'   => $results['threat_count'],
            'files_scanned'  => $results['files_scanned'],
            'scan_time'      => $results['scan_time'],
        ) );
    }

    public static function ajax_dismiss_threat() {
        shield_admin_only();
        check_ajax_referer( 'shield_ajax', 'nonce' );
        $idx  = intval( $_POST['threat_index'] ?? -1 );
        $scan = Shield_Scanner::get_last_scan();
        if ( $scan && isset( $scan['threats'][ $idx ] ) ) {
            array_splice( $scan['threats'], $idx, 1 );
            $scan['threat_count'] = count( $scan['threats'] );
            update_option( 'shield_last_scan', $scan );
        }
        wp_send_json_success();
    }

    public static function update_notice() {
        $release = Shield_Updater::get_latest_release();
        if ( ! $release ) return;
        $latest = ltrim( $release['tag_name'], 'v' );
        if ( version_compare( $latest, SHIELD_VERSION, '>' ) ) {
            $url = admin_url( 'update-core.php' );
            echo '<div class="notice notice-warning"><p><strong>Shield Security</strong> v' . esc_html( $latest ) . ' is available. <a href="' . esc_url( $url ) . '">Update now</a></p></div>';
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // STYLES
    // ═══════════════════════════════════════════════════════════════════
    public static function styles() {
        $screen = get_current_screen();
        if ( ! $screen || strpos( $screen->id, 'shield' ) === false ) return;
        ?>
        <style>
        #shield-wrap{max-width:960px;margin:30px auto;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
        .sh-card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px;margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
        .sh-card h2{margin-top:0;font-size:16px;display:flex;align-items:center;gap:8px}
        .sh-badge{display:inline-block;padding:3px 11px;border-radius:20px;font-size:12px;font-weight:700}
        .sh-red{background:#fdecea;color:#c0392b} .sh-ok{background:#d4edda;color:#155724}
        .sh-warn{background:#fff3cd;color:#856404} .sh-info{background:#d1ecf1;color:#0c5460}
        .sh-grey{background:#f0f0f0;color:#555}
        .sh-btn{display:inline-block;padding:9px 18px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;border:none;text-decoration:none;transition:opacity .15s}
        .sh-btn:hover{opacity:.88}
        .sh-btn-red{background:#e74c3c;color:#fff} .sh-btn-blue{background:#2271b1;color:#fff}
        .sh-btn-green{background:#27ae60;color:#fff} .sh-btn-grey{background:#f0f0f0;color:#333;border:1px solid #ccc}
        .sh-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}
        .sh-stat{text-align:center;padding:20px;border-radius:8px;border:1px solid #e0e0e0}
        .sh-stat .num{font-size:32px;font-weight:700;line-height:1}
        .sh-stat .lbl{font-size:12px;color:#666;margin-top:6px}
        table.sh-tbl{width:100%;border-collapse:collapse;font-size:13px}
        table.sh-tbl th{text-align:left;padding:9px 12px;background:#f7f7f7;border-bottom:2px solid #e2e2e2}
        table.sh-tbl td{padding:9px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top;word-break:break-all}
        table.sh-tbl tr:last-child td{border-bottom:none}
        .sh-field{margin-bottom:18px}
        .sh-field label{display:block;font-weight:600;font-size:13px;margin-bottom:5px}
        .sh-field .desc{font-size:12px;color:#888;margin-top:4px}
        .sh-field input[type=text],.sh-field input[type=email]{width:100%;max-width:400px;padding:8px 10px;border:1px solid #ccc;border-radius:5px;font-size:13px;box-sizing:border-box}
        .sh-saved{background:#d4edda;color:#155724;padding:10px 16px;border-radius:6px;margin-bottom:20px;font-size:13px;font-weight:600}
        .sh-err{background:#fdecea;color:#c0392b;padding:10px 16px;border-radius:6px;margin-bottom:20px;font-size:13px}
        .sh-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
        .sh-progress{display:none;height:4px;background:#e0e0e0;border-radius:2px;overflow:hidden;margin-top:12px}
        .sh-progress-bar{height:100%;background:#2271b1;width:0;animation:sh-progress 2s ease-in-out infinite}
        @keyframes sh-progress{0%{width:0%}50%{width:80%}100%{width:100%}}
        .sh-spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:sh-spin .6s linear infinite;vertical-align:middle;margin-right:6px}
        @keyframes sh-spin{to{transform:rotate(360deg)}}
        .sh-threat-row-critical{background:#fff8f8}
        .sh-threat-row-warning{background:#fffdf0}
        .sh-lic-box{border:2px solid;border-radius:8px;padding:20px;text-align:center;margin-bottom:24px}
        code{background:#f4f4f4;padding:1px 5px;border-radius:3px;font-size:12px}
        @media(max-width:700px){.sh-grid{grid-template-columns:1fr}}
        </style>
        <script>
        function shieldRunScan(btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="sh-spinner"></span>Scanning…';
            document.getElementById('sh-scan-progress').style.display = 'block';
            fetch(ajaxurl, {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'action=shield_run_scan&nonce=' + encodeURIComponent(shieldData.nonce)
            })
            .then(function(r){ return r.json(); })
            .then(function(data) {
                if (data.success) {
                    location.href = location.href.split('?')[0] + '?page=shield-scanner&scanned=1&threats=' + data.data.threat_count;
                } else {
                    btn.disabled = false;
                    btn.textContent = '🔍 Run Scan';
                    document.getElementById('sh-scan-progress').style.display = 'none';
                }
            })
            .catch(function() { location.reload(); });
        }
        </script>
        <?php
        wp_localize_script( 'jquery', 'shieldData', array( 'nonce' => wp_create_nonce( 'shield_ajax' ) ) );
    }

    // ═══════════════════════════════════════════════════════════════════
    // DASHBOARD PAGE
    // ═══════════════════════════════════════════════════════════════════
    public static function page_dashboard() {
        $scan     = Shield_Scanner::get_last_scan();
        $settings = shield_get_settings();
        $lic      = Shield_License::get_status_label();
        $threats  = $scan ? $scan['threat_count'] : null;
        $release  = Shield_Updater::get_latest_release();
        $latest   = $release ? ltrim( $release['tag_name'], 'v' ) : SHIELD_VERSION;
        $update_available = version_compare( $latest, SHIELD_VERSION, '>' );
        ?>
        <div id="shield-wrap">
        <h1>🛡 Shield Security <span style="font-size:13px;font-weight:400;color:#888;">v<?php echo esc_html( SHIELD_VERSION ); ?></span></h1>

        <!-- Stat Cards -->
        <div class="sh-grid">
            <div class="sh-stat <?php echo ( $threats === null ) ? '' : ( $threats > 0 ? 'sh-red' : 'sh-ok' ); ?>">
                <div class="num"><?php echo $threats === null ? '—' : intval( $threats ); ?></div>
                <div class="lbl">Threats Detected</div>
            </div>
            <div class="sh-stat" style="border-color:<?php echo esc_attr( $lic['color'] ); ?>">
                <div class="num" style="font-size:18px;color:<?php echo esc_attr( $lic['color'] ); ?>"><?php echo esc_html( $lic['label'] ); ?></div>
                <div class="lbl">License Status</div>
            </div>
            <div class="sh-stat <?php echo $update_available ? 'sh-warn' : 'sh-ok'; ?>">
                <div class="num" style="font-size:16px;"><?php echo $update_available ? 'v' . esc_html( $latest ) . ' ↑' : 'Up to date'; ?></div>
                <div class="lbl">Plugin Version</div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="sh-card">
            <h2>⚡ Quick Actions</h2>
            <div class="sh-actions">
                <a href="<?php echo admin_url( 'admin.php?page=shield-scanner' ); ?>" class="sh-btn sh-btn-blue">🔍 Go to Scanner</a>
                <a href="<?php echo admin_url( 'admin.php?page=shield-login' ); ?>" class="sh-btn sh-btn-blue">🔑 Login Security</a>
                <a href="<?php echo admin_url( 'admin.php?page=shield-settings' ); ?>" class="sh-btn sh-btn-grey">⚙ Settings</a>
                <?php if ( $update_available ) : ?>
                <a href="<?php echo admin_url( 'update-core.php' ); ?>" class="sh-btn sh-btn-green">⬆ Update to v<?php echo esc_html( $latest ); ?></a>
                <?php endif; ?>
            </div>
        </div>

        <!-- Recent Activity -->
        <div class="sh-card">
            <h2>📋 Recent Activity</h2>
            <?php
            $logs = get_option( 'shield_scan_log', array() );
            if ( empty( $logs ) ) {
                echo '<p style="color:#888;">No activity yet. Run a scan to get started.</p>';
            } else {
                echo '<table class="sh-tbl"><thead><tr><th>Time</th><th>Level</th><th>Message</th></tr></thead><tbody>';
                foreach ( array_slice( $logs, 0, 15 ) as $entry ) {
                    $color = $entry['level'] === 'warn' ? '#856404' : ( $entry['level'] === 'info' ? '#0c5460' : '#c0392b' );
                    echo '<tr><td style="white-space:nowrap;color:#888;">' . esc_html( $entry['time'] ) . '</td>';
                    echo '<td><span class="sh-badge sh-' . esc_attr( $entry['level'] === 'warn' ? 'warn' : 'info' ) . '">' . esc_html( strtoupper( $entry['level'] ) ) . '</span></td>';
                    echo '<td>' . esc_html( $entry['message'] ) . '</td></tr>';
                }
                echo '</tbody></table>';
            }
            ?>
        </div>

        <!-- Last Scan Summary -->
        <?php if ( $scan ) : ?>
        <div class="sh-card">
            <h2>🕐 Last Scan Summary</h2>
            <p style="font-size:13px;color:#666;">
                Completed: <strong><?php echo esc_html( $scan['completed_at'] ); ?></strong> &nbsp;·&nbsp;
                Files scanned: <strong><?php echo number_format( $scan['files_scanned'] ); ?></strong> &nbsp;·&nbsp;
                DB rows checked: <strong><?php echo number_format( $scan['db_rows_scanned'] ); ?></strong> &nbsp;·&nbsp;
                Time: <strong><?php echo esc_html( $scan['scan_time'] ); ?>s</strong>
            </p>
            <?php if ( $scan['threat_count'] > 0 ) : ?>
            <div style="margin-top:8px;">
                <span class="sh-badge sh-red">⚠ <?php echo intval( $scan['threat_count'] ); ?> active threat(s)</span>
                &nbsp; <a href="<?php echo admin_url( 'admin.php?page=shield-scanner' ); ?>">View &amp; clean →</a>
            </div>
            <?php else : ?>
            <span class="sh-badge sh-ok">✔ No threats found</span>
            <?php endif; ?>
        </div>
        <?php endif; ?>
        </div>
        <?php
    }

    // ═══════════════════════════════════════════════════════════════════
    // SCANNER PAGE
    // ═══════════════════════════════════════════════════════════════════
    public static function page_scanner() {
        $scan    = Shield_Scanner::get_last_scan();
        $scanned = isset( $_GET['scanned'] );
        $clean   = isset( $_GET['clean'] ) ? sanitize_key( $_GET['clean'] ) : '';
        ?>
        <div id="shield-wrap">
        <h1>🔍 Malware Scanner</h1>
        <p style="color:#666;margin-bottom:24px;">Scans plugin files, theme files, WordPress drop-ins, and the database for known malware signatures and suspicious patterns.</p>

        <?php if ( $scanned ) : ?>
            <?php $threats = intval( $_GET['threats'] ?? 0 ); ?>
            <div class="sh-saved" style="<?php echo $threats > 0 ? 'background:#fdecea;color:#c0392b;' : ''; ?>">
                <?php echo $threats > 0
                    ? '⚠ Scan complete — ' . $threats . ' threat(s) found. Review below.'
                    : '✔ Scan complete — no threats found. Your site looks clean.'; ?>
            </div>
        <?php endif; ?>

        <?php if ( $clean === 'all_done' ) : ?>
            <div class="sh-saved">✔ All threats cleaned successfully.</div>
        <?php elseif ( $clean === 'cleaned' ) : ?>
            <div class="sh-saved">✔ Threat removed.</div>
        <?php elseif ( $clean === 'error' ) : ?>
            <div class="sh-err">⚠ Could not remove threat automatically — review manually (may need SFTP).</div>
        <?php endif; ?>

        <!-- Run Scan Card -->
        <div class="sh-card">
            <h2>▶ Run a Scan</h2>
            <p style="font-size:13px;color:#555;">Scans: mu-plugins, plugins folder, active theme, wp-content drop-ins, wp-login.php, scatter directories, uploads (fake JPEGs), wp_options, meta tables, cron jobs, admin users.</p>
            <div class="sh-actions">
                <button type="button" class="sh-btn sh-btn-blue" onclick="shieldRunScan(this)">🔍 Run Full Scan</button>
                <?php if ( $scan && ! empty( $scan['threats'] ) ) : ?>
                <form method="post" style="display:inline">
                    <?php shield_nonce_field(); ?>
                    <input type="hidden" name="shield_action" value="clean_all">
                    <button type="submit" class="sh-btn sh-btn-red" onclick="return confirm('Remove all <?php echo intval( $scan['threat_count'] ); ?> threat(s) automatically?')">
                        🧹 Clean All (<?php echo intval( $scan['threat_count'] ); ?>)
                    </button>
                </form>
                <?php endif; ?>
            </div>
            <div id="sh-scan-progress" class="sh-progress"><div class="sh-progress-bar"></div></div>
            <?php if ( $scan ) : ?>
            <p style="font-size:12px;color:#aaa;margin-top:12px;">Last scan: <?php echo esc_html( $scan['completed_at'] ); ?> — <?php echo number_format( $scan['files_scanned'] ); ?> files, <?php echo esc_html( $scan['scan_time'] ); ?>s</p>
            <?php endif; ?>
        </div>

        <!-- Threat List -->
        <?php if ( $scan ) : ?>
        <div class="sh-card">
            <h2>
                ⚠ Scan Results
                <?php if ( $scan['threat_count'] > 0 ) : ?>
                <span class="sh-badge sh-red"><?php echo intval( $scan['threat_count'] ); ?> threat(s)</span>
                <?php else : ?>
                <span class="sh-badge sh-ok">Clean</span>
                <?php endif; ?>
            </h2>

            <?php if ( empty( $scan['threats'] ) ) : ?>
                <p style="color:#155724;">✔ No threats in last scan results.</p>
            <?php else : ?>
            <table class="sh-tbl">
                <thead><tr><th>Type</th><th>Severity</th><th>Location</th><th>Description</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ( $scan['threats'] as $i => $threat ) : ?>
                <tr class="sh-threat-row-<?php echo esc_attr( $threat['severity'] ?? 'warning' ); ?>">
                    <td><code><?php echo esc_html( $threat['type'] ); ?></code></td>
                    <td>
                        <?php if ( ( $threat['severity'] ?? '' ) === 'critical' ) : ?>
                            <span class="sh-badge sh-red">Critical</span>
                        <?php else : ?>
                            <span class="sh-badge sh-warn">Warning</span>
                        <?php endif; ?>
                    </td>
                    <td style="font-family:monospace;font-size:12px;"><?php echo esc_html( $threat['location'] ); ?></td>
                    <td><?php echo esc_html( $threat['description'] ); ?></td>
                    <td>
                        <form method="post" style="display:inline">
                            <?php shield_nonce_field(); ?>
                            <input type="hidden" name="shield_action"  value="clean_threat">
                            <input type="hidden" name="threat_index"   value="<?php echo intval( $i ); ?>">
                            <button type="submit" class="sh-btn sh-btn-red" style="padding:4px 10px;font-size:12px;"
                                onclick="return confirm('Remove this threat?')">Remove</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>
        <?php endif; ?>
        </div>
        <?php
    }

    // ═══════════════════════════════════════════════════════════════════
    // LOGIN SECURITY PAGE
    // ═══════════════════════════════════════════════════════════════════
    public static function page_login() {
        $settings = shield_get_settings();
        $saved    = isset( $_GET['shield_saved'] );
        ?>
        <div id="shield-wrap">
        <h1>🔑 Login Security</h1>
        <?php if ( $saved ) echo '<div class="sh-saved">✔ Login settings saved. Flush permalinks if the new URL does not work: Settings → Permalinks → Save.</div>'; ?>

        <div class="sh-card" style="border-left:4px solid #e74c3c;">
            <h2>⚠ Before Enabling</h2>
            <p style="font-size:13px;">After saving, your wp-admin login URL will change. <strong>Bookmark the new URL before saving.</strong> Your custom login URL will be: <code><?php echo esc_html( home_url( '/' . ( $settings['login_slug'] ?: 'site-login' ) ) ); ?></code></p>
        </div>

        <form method="post">
        <?php shield_nonce_field(); ?>
        <input type="hidden" name="shield_action" value="save_settings">

        <div class="sh-card">
            <h2>🔒 Custom Login URL</h2>
            <div class="sh-field">
                <label for="shield_login_slug">Custom Login Slug</label>
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="color:#888;font-size:13px;"><?php echo esc_html( trailingslashit( home_url() ) ); ?></span>
                    <input type="text" id="shield_login_slug" name="shield_login_slug"
                        value="<?php echo esc_attr( $settings['login_slug'] ); ?>"
                        placeholder="site-login" style="max-width:200px;">
                </div>
                <div class="desc">Replace <code>/wp-login.php</code> with this URL. Use only letters, numbers, and hyphens.</div>
            </div>
            <div class="sh-field">
                <label>
                    <input type="checkbox" name="shield_hide_login" value="1" <?php checked( $settings['hide_login'], '1' ); ?>>
                    &nbsp;Enable login URL hardening
                </label>
                <div class="desc">Activates the custom login URL and blocks direct access to <code>/wp-login.php</code> and <code>/wp-admin</code> for non-logged-in users.</div>
            </div>
        </div>

        <div class="sh-card">
            <h2>🤖 Bot &amp; Unknown Visitor Protection</h2>
            <div class="sh-field">
                <label>
                    <input type="checkbox" name="shield_bot_redirect_404" value="1" <?php checked( $settings['bot_redirect_404'], '1' ); ?>>
                    &nbsp;Return 404 to bots and unknown visitors accessing <code>/wp-login.php</code>
                </label>
                <div class="desc">Detected bots and automated scanners receive a 404 Not Found response instead of a redirect. Human visitors are redirected to the custom login URL. Detected by User-Agent string.</div>
            </div>
        </div>

        <button type="submit" class="sh-btn sh-btn-blue">💾 Save Login Settings</button>
        </form>

        <!-- Current Status -->
        <div class="sh-card" style="margin-top:24px;">
            <h2>ℹ Current Status</h2>
            <table class="sh-tbl"><tbody>
                <tr><td>Login hardening</td><td><?php echo $settings['hide_login'] === '1' ? '<span class="sh-badge sh-ok">Enabled</span>' : '<span class="sh-badge sh-grey">Disabled</span>'; ?></td></tr>
                <tr><td>Custom login URL</td><td><?php echo $settings['login_slug'] ? '<code>' . esc_html( home_url( '/' . $settings['login_slug'] ) ) . '</code>' : '<span style="color:#888">Not configured</span>'; ?></td></tr>
                <tr><td>Bot 404 redirect</td><td><?php echo $settings['bot_redirect_404'] === '1' ? '<span class="sh-badge sh-ok">Enabled</span>' : '<span class="sh-badge sh-grey">Disabled</span>'; ?></td></tr>
                <tr><td>wp-admin blocked for guests</td><td><?php echo $settings['hide_login'] === '1' ? '<span class="sh-badge sh-ok">Yes</span>' : '<span class="sh-badge sh-grey">No</span>'; ?></td></tr>
            </tbody></table>
        </div>
        </div>
        <?php
    }

    // ═══════════════════════════════════════════════════════════════════
    // SETTINGS PAGE
    // ═══════════════════════════════════════════════════════════════════
    public static function page_settings() {
        $settings = shield_get_settings();
        $saved    = isset( $_GET['shield_saved'] );
        ?>
        <div id="shield-wrap">
        <h1>⚙ Settings</h1>
        <?php if ( $saved ) echo '<div class="sh-saved">✔ Settings saved.</div>'; ?>
        <form method="post">
        <?php shield_nonce_field(); ?>
        <input type="hidden" name="shield_action" value="save_settings">

        <div class="sh-card">
            <h2>🔄 Auto-Updates</h2>
            <div class="sh-field">
                <label><input type="checkbox" name="shield_auto_update" value="1" <?php checked( $settings['auto_update'], '1' ); ?>>
                &nbsp;Enable automatic plugin updates from GitHub</label>
                <div class="desc">When a new version is released on GitHub, WordPress will show an update notification. Auto-update requires a valid license.</div>
            </div>
        </div>

        <div class="sh-card">
            <h2>📧 Email Alerts</h2>
            <div class="sh-field">
                <label><input type="checkbox" name="shield_email_alerts" value="1" <?php checked( $settings['email_alerts'], '1' ); ?>>
                &nbsp;Send email alert when threats are detected during a scan</label>
            </div>
            <div class="sh-field">
                <label for="shield_alert_email">Alert Email Address</label>
                <input type="email" id="shield_alert_email" name="shield_alert_email" value="<?php echo esc_attr( $settings['alert_email'] ); ?>">
                <div class="desc">Default is the WordPress admin email.</div>
            </div>
        </div>

        <button type="submit" class="sh-btn sh-btn-blue">💾 Save Settings</button>
        </form>
        </div>
        <?php
    }

    // ═══════════════════════════════════════════════════════════════════
    // LICENSE PAGE
    // ═══════════════════════════════════════════════════════════════════
    public static function page_license() {
        $lic_data = get_option( SHIELD_LIC_OPT, array() );
        $is_valid = Shield_License::is_valid();
        $status   = Shield_License::get_status_label();
        $msg      = isset( $_GET['lic_msg'] ) ? sanitize_key( $_GET['lic_msg'] ) : '';
        ?>
        <div id="shield-wrap">
        <h1>🔐 License</h1>

        <?php if ( $msg === 'activated' )   echo '<div class="sh-saved">✔ License activated successfully.</div>'; ?>
        <?php if ( $msg === 'deactivated' ) echo '<div class="sh-saved" style="background:#d1ecf1;color:#0c5460;">License deactivated.</div>'; ?>
        <?php if ( $msg === 'invalid' )     echo '<div class="sh-err">⚠ Invalid license key. Please check your key and try again.</div>'; ?>

        <!-- Status Box -->
        <div class="sh-lic-box" style="border-color:<?php echo esc_attr( $status['color'] ); ?>;">
            <div style="font-size:28px;font-weight:700;color:<?php echo esc_attr( $status['color'] ); ?>;">
                <?php echo esc_html( $status['label'] ); ?>
            </div>
            <?php if ( ! empty( $lic_data['key'] ) ) : ?>
            <div style="margin-top:8px;font-size:13px;color:#888;">
                Key: <code><?php echo esc_html( substr( $lic_data['key'], 0, 8 ) . str_repeat( '•', 16 ) ); ?></code>
                &nbsp;·&nbsp; Domain: <code><?php echo esc_html( $lic_data['domain'] ?? home_url() ); ?></code>
            </div>
            <?php endif; ?>
        </div>

        <?php if ( ! $is_valid ) : ?>
        <!-- Activation Form -->
        <div class="sh-card">
            <h2>🔑 Activate License</h2>
            <p style="font-size:13px;color:#555;">Enter your license key to enable auto-updates and full scanning features. Purchase at <a href="https://nextnovatechnologies.com" target="_blank">nextnovatechnologies.com</a>.</p>
            <form method="post">
                <?php shield_nonce_field(); ?>
                <input type="hidden" name="shield_license_action" value="activate">
                <div class="sh-field">
                    <label for="shield_license_key">License Key</label>
                    <input type="text" id="shield_license_key" name="shield_license_key" placeholder="XXXX-XXXX-XXXX-XXXX" style="max-width:340px;font-family:monospace;">
                </div>
                <button type="submit" class="sh-btn sh-btn-blue">Activate License</button>
            </form>
        </div>
        <?php else : ?>
        <!-- Deactivation -->
        <div class="sh-card">
            <h2>✔ License Active</h2>
            <p style="font-size:13px;">Your license is valid and active on this domain. Auto-updates are enabled.</p>
            <form method="post">
                <?php shield_nonce_field(); ?>
                <input type="hidden" name="shield_license_action" value="deactivate">
                <button type="submit" class="sh-btn sh-btn-grey" onclick="return confirm('Deactivate this license on this domain?')">Deactivate</button>
            </form>
        </div>
        <?php endif; ?>

        <!-- What's included -->
        <div class="sh-card">
            <h2>📦 What Your License Includes</h2>
            <table class="sh-tbl"><tbody>
                <tr><td>✔ Deep malware scanner</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ One-click threat removal</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Auto-updates via GitHub</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Login URL hardening</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Email threat alerts</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Support from Next Nova Technologies</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
            </tbody></table>
        </div>
        </div>
        <?php
    }
}
