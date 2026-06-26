<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Admin UI — PHP 7.0 compatible
 * Dashboard, Scanner (chunked step progress), Login Security, Settings, License
 */
class Shield_Admin_UI {

    public static function init() {
        add_action( 'admin_menu',    array( __CLASS__, 'register_menu' ) );
        add_action( 'admin_head',    array( __CLASS__, 'styles' ) );
        add_action( 'admin_init',    array( __CLASS__, 'handle_actions' ) );
        add_action( 'admin_notices', array( __CLASS__, 'update_notice' ) );

        // AJAX — step-based scan
        add_action( 'wp_ajax_shield_scan_step',     array( __CLASS__, 'ajax_scan_step' ) );
        add_action( 'wp_ajax_shield_dismiss_threat', array( __CLASS__, 'ajax_dismiss_threat' ) );
    }

    public static function register_menu() {
        add_menu_page(
            'Shield Security', '🛡 Shield', 'manage_options',
            'shield-security', array( __CLASS__, 'page_dashboard' ),
            'dashicons-shield-alt', 80
        );
        add_submenu_page( 'shield-security', 'Dashboard',      'Dashboard',      'manage_options', 'shield-security', array( __CLASS__, 'page_dashboard' ) );
        add_submenu_page( 'shield-security', 'Scanner',        'Scanner',        'manage_options', 'shield-scanner',  array( __CLASS__, 'page_scanner' ) );
        add_submenu_page( 'shield-security', 'Login Security', 'Login Security', 'manage_options', 'shield-login',    array( __CLASS__, 'page_login' ) );
        add_submenu_page( 'shield-security', 'Settings',       'Settings',       'manage_options', 'shield-settings', array( __CLASS__, 'page_settings' ) );
        add_submenu_page( 'shield-security', 'License',        'License',        'manage_options', 'shield-license',  array( __CLASS__, 'page_license' ) );
    }

    // ── AJAX: run one scan step ───────────────────────────────────────
    public static function ajax_scan_step() {
        shield_admin_only();
        check_ajax_referer( 'shield_ajax', 'nonce' );
        $step = sanitize_key( $_POST['step'] ?? '' );
        if ( ! array_key_exists( $step, Shield_Scanner::get_steps() ) ) {
            wp_send_json_error( array( 'message' => 'Unknown step: ' . $step ) );
        }
        $result = Shield_Scanner::run_step( $step );
        wp_send_json_success( $result );
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

    // ── Non-AJAX form actions (clean threat, clean all) ───────────────
    public static function handle_actions() {
        if ( ! isset( $_POST['shield_action'] ) ) return;
        shield_admin_only();
        if ( ! shield_verify_nonce() ) wp_die( 'Bad nonce' );

        $action = sanitize_key( $_POST['shield_action'] );

        if ( $action === 'clean_threat' ) {
            $scan = Shield_Scanner::get_last_scan();
            $idx  = intval( $_POST['threat_index'] ?? -1 );
            if ( $scan && isset( $scan['threats'][ $idx ] ) ) {
                $result = Shield_Cleanup::remove_threat( $scan['threats'][ $idx ] );
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
                $scan['threats']      = array();
                $scan['threat_count'] = 0;
                update_option( 'shield_last_scan', $scan );
            }
            wp_redirect( add_query_arg( array( 'page' => 'shield-scanner', 'clean' => 'all_done' ), admin_url( 'admin.php' ) ) );
            exit;
        }

        // Settings save
        if ( $action === 'save_settings' ) {
            Shield_Settings::handle_post();
        }
    }

    public static function update_notice() {
        $release = Shield_Updater::get_latest_release();
        if ( ! $release ) return;
        $latest = ltrim( $release['tag_name'], 'v' );
        if ( version_compare( $latest, SHIELD_VERSION, '>' ) ) {
            echo '<div class="notice notice-warning"><p><strong>Shield Security</strong> v' . esc_html( $latest ) . ' is available. <a href="' . esc_url( admin_url( 'update-core.php' ) ) . '">Update now</a></p></div>';
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // STYLES + JS
    // ═══════════════════════════════════════════════════════════════════
    public static function styles() {
        $screen = get_current_screen();
        if ( ! $screen || strpos( $screen->id, 'shield' ) === false ) return;
        ?>
        <style>
        #shield-wrap{max-width:960px;margin:30px auto;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
        .sh-card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px;margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
        .sh-card h2{margin-top:0;font-size:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
        .sh-badge{display:inline-block;padding:3px 11px;border-radius:20px;font-size:12px;font-weight:700}
        .sh-red{background:#fdecea;color:#c0392b} .sh-ok{background:#d4edda;color:#155724}
        .sh-warn{background:#fff3cd;color:#856404} .sh-info{background:#d1ecf1;color:#0c5460}
        .sh-grey{background:#f0f0f0;color:#555}
        .sh-btn{display:inline-block;padding:9px 18px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;border:none;text-decoration:none;transition:opacity .15s}
        .sh-btn:hover{opacity:.88}
        .sh-btn-red{background:#e74c3c;color:#fff} .sh-btn-blue{background:#2271b1;color:#fff}
        .sh-btn-green{background:#27ae60;color:#fff} .sh-btn-grey{background:#f0f0f0;color:#333;border:1px solid #ccc}
        .sh-btn:disabled{opacity:.5;cursor:not-allowed}
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
        .sh-threat-row-critical{background:#fff8f8}
        .sh-threat-row-warning{background:#fffdf0}
        .sh-lic-box{border:2px solid;border-radius:8px;padding:20px;text-align:center;margin-bottom:24px}
        code{background:#f4f4f4;padding:1px 5px;border-radius:3px;font-size:12px}
        @media(max-width:700px){.sh-grid{grid-template-columns:1fr}}

        /* ── Step progress list ───────────────────────────── */
        .sh-steps{list-style:none;margin:0;padding:0}
        .sh-step{display:flex;align-items:center;gap:14px;padding:11px 14px;border-radius:7px;margin-bottom:6px;font-size:13px;background:#f9f9f9;border:1px solid #eee;transition:background .2s}
        .sh-step.step-waiting  {color:#999}
        .sh-step.step-running  {background:#f0f6ff;border-color:#b8d4f5;color:#1a4a8a;font-weight:600}
        .sh-step.step-done     {background:#f0fff4;border-color:#b7e4c7;color:#155724}
        .sh-step.step-error    {background:#fff0f0;border-color:#f5c6cb;color:#c0392b}
        .sh-step-icon{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
        .step-waiting  .sh-step-icon{background:#e5e5e5;color:#aaa}
        .step-running  .sh-step-icon{background:#2271b1;color:#fff}
        .step-done     .sh-step-icon{background:#27ae60;color:#fff}
        .step-error    .sh-step-icon{background:#e74c3c;color:#fff}
        .sh-step-label{flex:1}
        .sh-step-meta{font-size:11px;opacity:.75;white-space:nowrap}
        .sh-step-threat{font-size:11px;font-weight:700;color:#c0392b;background:#fdecea;padding:1px 7px;border-radius:10px}

        /* spinner inside running step icon */
        .sh-spin{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:sh-spin .6s linear infinite}
        @keyframes sh-spin{to{transform:rotate(360deg)}}

        /* overall progress bar */
        .sh-overall-bar{height:6px;background:#e0e0e0;border-radius:3px;overflow:hidden;margin:16px 0 4px}
        .sh-overall-fill{height:100%;background:linear-gradient(90deg,#2271b1,#27ae60);border-radius:3px;transition:width .4s ease;width:0%}
        .sh-scan-summary{font-size:13px;color:#555;margin-top:4px;min-height:20px}
        </style>

        <script>
        (function(){
        var shieldNonce  = '<?php echo esc_js( wp_create_nonce( 'shield_ajax' ) ); ?>';
        var shieldAjax   = '<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>';
        var shieldSteps  = <?php echo wp_json_encode( array_keys( Shield_Scanner::get_steps() ) ); ?>;
        var shieldLabels = <?php echo wp_json_encode( Shield_Scanner::get_steps() ); ?>;
        var scanActive   = false;
        var stepsDone    = 0;
        var totalThreats = 0;
        var totalFiles   = 0;

        function el(id){ return document.getElementById(id); }

        function setStepState(step, state, meta, threats){
            var row  = el('sh-step-' + step);
            var icon = el('sh-icon-' + step);
            var metaEl = el('sh-meta-' + step);
            var threatEl = el('sh-threat-' + step);
            if(!row) return;
            row.className = 'sh-step step-' + state;
            if(state === 'waiting') { icon.innerHTML = '○'; }
            if(state === 'running') { icon.innerHTML = '<span class="sh-spin"></span>'; }
            if(state === 'done')    { icon.innerHTML = '✔'; }
            if(state === 'error')   { icon.innerHTML = '✘'; }
            if(meta && metaEl)    metaEl.textContent = meta;
            if(threats && threatEl && threats > 0){
                threatEl.textContent = threats + ' threat' + (threats>1?'s':'') + ' found';
                threatEl.style.display = 'inline-block';
            }
        }

        function updateBar(done, total){
            var pct = Math.round((done / total) * 100);
            var fill = el('sh-overall-fill');
            if(fill) fill.style.width = pct + '%';
            var sumEl = el('sh-scan-summary');
            if(sumEl) sumEl.textContent = done + ' of ' + total + ' steps complete' +
                (totalThreats > 0 ? ' · ' + totalThreats + ' threat(s) found' : '') +
                (totalFiles > 0 ? ' · ' + totalFiles + ' file(s) scanned' : '');
        }

        function runStep(index){
            if(index >= shieldSteps.length){ finishScan(); return; }
            var step = shieldSteps[index];
            setStepState(step, 'running', 'Scanning…', 0);
            updateBar(index, shieldSteps.length);

            var body = 'action=shield_scan_step&nonce=' + encodeURIComponent(shieldNonce) + '&step=' + encodeURIComponent(step);
            fetch(shieldAjax, {
                method: 'POST',
                headers: {'Content-Type':'application/x-www-form-urlencoded'},
                body: body
            })
            .then(function(r){ return r.json(); })
            .then(function(data){
                if(data.success){
                    var d = data.data;
                    stepsDone++;
                    totalThreats += (d.threats_found || 0);
                    totalFiles   += (d.files_scanned || 0);
                    var meta = d.time ? d.time + 's' : '';
                    if(d.files_scanned) meta = d.files_scanned + ' file(s) · ' + meta;
                    setStepState(step, 'done', meta, d.threats_found || 0);
                    updateBar(stepsDone, shieldSteps.length);

                    if(d.final){
                        finishScan(d.threat_count);
                    } else {
                        runStep(index + 1);
                    }
                } else {
                    setStepState(step, 'error', 'Error — check server logs', 0);
                    updateBar(stepsDone, shieldSteps.length);
                    setScanError('Step "' + shieldLabels[step] + '" failed. Check your server error log. You can try again.');
                    enableRunBtn();
                }
            })
            .catch(function(err){
                setStepState(step, 'error', 'Network error', 0);
                setScanError('Network error during "' + shieldLabels[step] + '": ' + err.message + '. Check your connection and try again.');
                enableRunBtn();
            });
        }

        function finishScan(threatCount){
            var fill = el('sh-overall-fill');
            if(fill){ fill.style.width='100%'; fill.style.background='#27ae60'; }
            var sumEl = el('sh-scan-summary');
            if(sumEl){
                var tc = (typeof threatCount !== 'undefined') ? threatCount : totalThreats;
                sumEl.textContent = 'Scan complete · ' + totalFiles + ' file(s) scanned · ' +
                    (tc > 0 ? tc + ' threat(s) found — see results below' : 'No threats found ✔');
                sumEl.style.color = tc > 0 ? '#c0392b' : '#155724';
            }
            var resultsNote = el('sh-results-note');
            if(resultsNote) resultsNote.style.display = 'block';

            // Reload the results section via a lightweight page refresh after short delay
            setTimeout(function(){
                var url = window.location.href.split('?')[0] + '?page=shield-scanner&scanned=1&threats=' + (typeof threatCount !== 'undefined' ? threatCount : totalThreats);
                window.location.href = url;
            }, 1200);
        }

        function setScanError(msg){
            var el2 = el('sh-scan-error');
            if(el2){ el2.textContent = msg; el2.style.display='block'; }
        }

        function enableRunBtn(){
            var btn = el('sh-run-btn');
            if(btn){ btn.disabled = false; btn.textContent = '🔍 Run Scan Again'; }
            scanActive = false;
        }

        window.shieldStartScan = function(btn){
            if(scanActive) return;
            scanActive   = true;
            stepsDone    = 0;
            totalThreats = 0;
            totalFiles   = 0;
            btn.disabled = true;
            btn.textContent = 'Scanning…';

            // Reset all step states
            for(var i=0; i<shieldSteps.length; i++){
                setStepState(shieldSteps[i], 'waiting', '', 0);
                var te = el('sh-threat-' + shieldSteps[i]);
                if(te) te.style.display = 'none';
            }
            var fill = el('sh-overall-fill');
            if(fill){ fill.style.width='0%'; fill.style.background='linear-gradient(90deg,#2271b1,#27ae60)'; }
            var errEl = el('sh-scan-error');
            if(errEl) errEl.style.display = 'none';
            var rn = el('sh-results-note');
            if(rn) rn.style.display = 'none';

            // Start from first step
            runStep(0);
        };
        })();
        </script>
        <?php
    }

    // ═══════════════════════════════════════════════════════════════════
    // DASHBOARD
    // ═══════════════════════════════════════════════════════════════════
    public static function page_dashboard() {
        $scan    = Shield_Scanner::get_last_scan();
        $lic     = Shield_License::get_status_label();
        $threats = $scan ? $scan['threat_count'] : null;
        $release = Shield_Updater::get_latest_release();
        $latest  = $release ? ltrim( $release['tag_name'], 'v' ) : SHIELD_VERSION;
        $update  = version_compare( $latest, SHIELD_VERSION, '>' );
        ?>
        <div id="shield-wrap">
        <h1>🛡 Shield Security <span style="font-size:13px;font-weight:400;color:#888;">v<?php echo esc_html( SHIELD_VERSION ); ?></span></h1>

        <div class="sh-grid">
            <div class="sh-stat <?php echo ( $threats === null ) ? '' : ( $threats > 0 ? 'sh-red' : 'sh-ok' ); ?>">
                <div class="num"><?php echo $threats === null ? '—' : intval( $threats ); ?></div>
                <div class="lbl">Threats Detected</div>
            </div>
            <div class="sh-stat" style="border-color:<?php echo esc_attr( $lic['color'] ); ?>">
                <div class="num" style="font-size:18px;color:<?php echo esc_attr( $lic['color'] ); ?>"><?php echo esc_html( $lic['label'] ); ?></div>
                <div class="lbl">License Status</div>
            </div>
            <div class="sh-stat <?php echo $update ? 'sh-warn' : 'sh-ok'; ?>">
                <div class="num" style="font-size:16px;"><?php echo $update ? 'v' . esc_html( $latest ) . ' ↑' : 'Up to date'; ?></div>
                <div class="lbl">Plugin Version</div>
            </div>
        </div>

        <div class="sh-card">
            <h2>⚡ Quick Actions</h2>
            <div class="sh-actions">
                <a href="<?php echo admin_url( 'admin.php?page=shield-scanner' ); ?>" class="sh-btn sh-btn-blue">🔍 Scanner</a>
                <a href="<?php echo admin_url( 'admin.php?page=shield-login' ); ?>"   class="sh-btn sh-btn-blue">🔑 Login Security</a>
                <a href="<?php echo admin_url( 'admin.php?page=shield-settings' ); ?>" class="sh-btn sh-btn-grey">⚙ Settings</a>
                <?php if ( $update ) : ?>
                <a href="<?php echo admin_url( 'update-core.php' ); ?>" class="sh-btn sh-btn-green">⬆ Update to v<?php echo esc_html( $latest ); ?></a>
                <?php endif; ?>
            </div>
        </div>

        <div class="sh-card">
            <h2>📋 Recent Activity</h2>
            <?php
            $logs = get_option( 'shield_scan_log', array() );
            if ( empty( $logs ) ) {
                echo '<p style="color:#888;">No activity yet. Run a scan to get started.</p>';
            } else {
                echo '<table class="sh-tbl"><thead><tr><th>Time</th><th>Level</th><th>Message</th></tr></thead><tbody>';
                foreach ( array_slice( $logs, 0, 15 ) as $entry ) {
                    $badge = $entry['level'] === 'warn' ? 'sh-warn' : 'sh-info';
                    echo '<tr><td style="white-space:nowrap;color:#888;">' . esc_html( $entry['time'] ) . '</td>';
                    echo '<td><span class="sh-badge ' . $badge . '">' . esc_html( strtoupper( $entry['level'] ) ) . '</span></td>';
                    echo '<td>' . esc_html( $entry['message'] ) . '</td></tr>';
                }
                echo '</tbody></table>';
            }
            ?>
        </div>

        <?php if ( $scan ) : ?>
        <div class="sh-card">
            <h2>🕐 Last Scan</h2>
            <p style="font-size:13px;color:#666;">
                Completed: <strong><?php echo esc_html( $scan['completed_at'] ); ?></strong> &nbsp;·&nbsp;
                Files: <strong><?php echo number_format( $scan['files_scanned'] ); ?></strong> &nbsp;·&nbsp;
                DB rows: <strong><?php echo number_format( $scan['db_rows_scanned'] ); ?></strong>
            </p>
            <?php if ( $scan['threat_count'] > 0 ) : ?>
            <span class="sh-badge sh-red">⚠ <?php echo intval( $scan['threat_count'] ); ?> active threat(s)</span>
            &nbsp; <a href="<?php echo admin_url( 'admin.php?page=shield-scanner' ); ?>">View &amp; clean →</a>
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
        $steps   = Shield_Scanner::get_steps();
        $scanned = isset( $_GET['scanned'] );
        $clean   = isset( $_GET['clean'] ) ? sanitize_key( $_GET['clean'] ) : '';
        ?>
        <div id="shield-wrap">
        <h1>🔍 Malware Scanner</h1>

        <?php if ( $clean === 'all_done' ) : ?>
            <div class="sh-saved">✔ All threats cleaned successfully.</div>
        <?php elseif ( $clean === 'cleaned' ) : ?>
            <div class="sh-saved">✔ Threat removed.</div>
        <?php elseif ( $clean === 'error' ) : ?>
            <div class="sh-err">⚠ Could not remove threat automatically — check file permissions or use SFTP.</div>
        <?php endif; ?>

        <!-- Run Scan Card -->
        <div class="sh-card">
            <h2>▶ Run a Full Scan</h2>
            <p style="font-size:13px;color:#555;margin-bottom:16px;">
                The scan runs in <strong><?php echo count( $steps ); ?> separate steps</strong> so it never times out.
                Each step completes independently and shows its result in real time below.
            </p>

            <div class="sh-actions" style="margin-bottom:16px;">
                <button id="sh-run-btn" type="button" class="sh-btn sh-btn-blue" onclick="shieldStartScan(this)">
                    🔍 Run Full Scan
                </button>
                <?php if ( $scan && ! empty( $scan['threats'] ) ) : ?>
                <form method="post" style="display:inline;">
                    <?php shield_nonce_field(); ?>
                    <input type="hidden" name="shield_action" value="clean_all">
                    <button type="submit" class="sh-btn sh-btn-red"
                        onclick="return confirm('Remove all <?php echo intval( $scan['threat_count'] ); ?> threat(s) now?')">
                        🧹 Clean All Threats (<?php echo intval( $scan['threat_count'] ); ?>)
                    </button>
                </form>
                <?php endif; ?>
            </div>

            <!-- Overall progress bar -->
            <div class="sh-overall-bar"><div id="sh-overall-fill" class="sh-overall-fill"></div></div>
            <div id="sh-scan-summary" class="sh-scan-summary"></div>
            <div id="sh-scan-error" class="sh-err" style="display:none;margin-top:12px;"></div>
            <div id="sh-results-note" style="display:none;margin-top:10px;font-size:13px;color:#155724;">
                ✔ Scan finished — loading results…
            </div>

            <!-- Step list -->
            <ul class="sh-steps" style="margin-top:20px;">
                <?php foreach ( $steps as $key => $label ) : ?>
                <li id="sh-step-<?php echo esc_attr( $key ); ?>" class="sh-step step-waiting">
                    <span id="sh-icon-<?php echo esc_attr( $key ); ?>" class="sh-step-icon">○</span>
                    <span class="sh-step-label"><?php echo esc_html( $label ); ?></span>
                    <span id="sh-threat-<?php echo esc_attr( $key ); ?>" class="sh-step-threat" style="display:none;"></span>
                    <span id="sh-meta-<?php echo esc_attr( $key ); ?>" class="sh-step-meta"></span>
                </li>
                <?php endforeach; ?>
            </ul>

            <?php if ( $scan ) : ?>
            <p style="font-size:12px;color:#aaa;margin-top:16px;margin-bottom:0;">
                Last scan: <?php echo esc_html( $scan['completed_at'] ); ?>
                &nbsp;·&nbsp; <?php echo number_format( $scan['files_scanned'] ); ?> files scanned
                &nbsp;·&nbsp; <?php echo number_format( $scan['db_rows_scanned'] ); ?> DB rows checked
            </p>
            <?php endif; ?>
        </div>

        <!-- Threat Results -->
        <?php if ( $scanned || ( $scan && ! empty( $scan['threats'] ) ) ) : ?>
        <div class="sh-card">
            <h2>
                ⚠ Scan Results
                <?php if ( $scan && $scan['threat_count'] > 0 ) : ?>
                    <span class="sh-badge sh-red"><?php echo intval( $scan['threat_count'] ); ?> threat(s) found</span>
                <?php else : ?>
                    <span class="sh-badge sh-ok">✔ Clean</span>
                <?php endif; ?>
            </h2>

            <?php if ( empty( $scan['threats'] ) ) : ?>
                <p style="color:#155724;">✔ No threats detected in the last scan.</p>
            <?php else : ?>
            <p style="font-size:13px;color:#666;margin-bottom:14px;">
                Review each threat below. Click <strong>Remove</strong> to let Shield clean it automatically,
                or dismiss if you've verified it's safe.
            </p>
            <table class="sh-tbl">
                <thead>
                    <tr>
                        <th style="width:100px;">Type</th>
                        <th style="width:90px;">Severity</th>
                        <th>Location</th>
                        <th>Description</th>
                        <th style="width:120px;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ( $scan['threats'] as $i => $threat ) :
                    $sev = isset( $threat['severity'] ) ? $threat['severity'] : 'warning';
                ?>
                <tr class="sh-threat-row-<?php echo esc_attr( $sev ); ?>">
                    <td><code><?php echo esc_html( $threat['type'] ); ?></code></td>
                    <td>
                        <?php if ( $sev === 'critical' ) : ?>
                            <span class="sh-badge sh-red">Critical</span>
                        <?php else : ?>
                            <span class="sh-badge sh-warn">Warning</span>
                        <?php endif; ?>
                    </td>
                    <td style="font-family:monospace;font-size:12px;"><?php echo esc_html( $threat['location'] ); ?></td>
                    <td style="font-size:13px;"><?php echo esc_html( $threat['description'] ); ?></td>
                    <td>
                        <form method="post" style="display:inline;">
                            <?php shield_nonce_field(); ?>
                            <input type="hidden" name="shield_action" value="clean_threat">
                            <input type="hidden" name="threat_index"  value="<?php echo intval( $i ); ?>">
                            <button type="submit" class="sh-btn sh-btn-red" style="padding:4px 10px;font-size:12px;"
                                onclick="return confirm('Remove this threat?')">Remove</button>
                        </form>
                        &nbsp;
                        <button type="button" class="sh-btn sh-btn-grey" style="padding:4px 10px;font-size:12px;"
                            onclick="if(confirm('Dismiss this threat? It will be removed from the list but not cleaned.')){
                                var f=document.createElement('form');f.method='post';f.innerHTML='<?php echo esc_js( '<input type=\'hidden\' name=\'shield_action\' value=\'clean_threat\'>' ); ?>';
                                document.body.appendChild(f);f.submit();
                            }">Dismiss</button>
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
        <?php if ( $saved ) : ?>
        <div class="sh-saved">✔ Settings saved. If the custom login URL doesn't work, go to Settings → Permalinks → Save Changes to flush rewrite rules.</div>
        <?php endif; ?>

        <div class="sh-card" style="border-left:4px solid #e74c3c;">
            <h2>⚠ Before Enabling</h2>
            <p style="font-size:13px;">Once saved your login URL changes. <strong>Bookmark your new login URL first:</strong>
            <code><?php echo esc_html( home_url( '/' . ( $settings['login_slug'] ?: 'site-login' ) ) ); ?></code></p>
        </div>

        <form method="post">
        <?php shield_nonce_field(); ?>
        <input type="hidden" name="shield_action" value="save_settings">

        <div class="sh-card">
            <h2>🔒 Custom Login URL</h2>
            <div class="sh-field">
                <label for="shield_login_slug">Login Slug</label>
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                    <span style="color:#888;font-size:13px;"><?php echo esc_html( trailingslashit( home_url() ) ); ?></span>
                    <input type="text" id="shield_login_slug" name="shield_login_slug"
                        value="<?php echo esc_attr( $settings['login_slug'] ); ?>" placeholder="site-login" style="max-width:180px;">
                </div>
                <div class="desc">Letters, numbers, and hyphens only. Replaces <code>/wp-login.php</code>.</div>
            </div>
            <div class="sh-field">
                <label>
                    <input type="checkbox" name="shield_hide_login" value="1" <?php checked( $settings['hide_login'], '1' ); ?>>
                    &nbsp;Enable login URL hardening
                </label>
                <div class="desc">Activates the custom URL and blocks direct access to <code>/wp-login.php</code> and <code>/wp-admin</code> for non-logged-in users.</div>
            </div>
        </div>

        <div class="sh-card">
            <h2>🤖 Bot Protection</h2>
            <div class="sh-field">
                <label>
                    <input type="checkbox" name="shield_bot_redirect_404" value="1" <?php checked( $settings['bot_redirect_404'], '1' ); ?>>
                    &nbsp;Return 404 to bots accessing <code>/wp-login.php</code> or <code>/wp-admin</code>
                </label>
                <div class="desc">Bots and scanners see a 404 Not Found. Human visitors are redirected to your custom login URL.</div>
            </div>
        </div>

        <button type="submit" class="sh-btn sh-btn-blue">💾 Save Login Settings</button>
        </form>

        <div class="sh-card" style="margin-top:24px;">
            <h2>ℹ Current Status</h2>
            <table class="sh-tbl"><tbody>
                <tr><td>Login hardening</td><td><?php echo $settings['hide_login'] === '1' ? '<span class="sh-badge sh-ok">Enabled</span>' : '<span class="sh-badge sh-grey">Disabled</span>'; ?></td></tr>
                <tr><td>Custom login URL</td><td><?php echo $settings['login_slug'] ? '<code>' . esc_html( home_url( '/' . $settings['login_slug'] ) ) . '</code>' : '<span style="color:#888">Not set</span>'; ?></td></tr>
                <tr><td>Bot 404 redirect</td><td><?php echo $settings['bot_redirect_404'] === '1' ? '<span class="sh-badge sh-ok">Enabled</span>' : '<span class="sh-badge sh-grey">Disabled</span>'; ?></td></tr>
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
                <div class="desc">New versions appear in Dashboard → Updates. Requires a valid license.</div>
            </div>
        </div>

        <div class="sh-card">
            <h2>📧 Email Alerts</h2>
            <div class="sh-field">
                <label><input type="checkbox" name="shield_email_alerts" value="1" <?php checked( $settings['email_alerts'], '1' ); ?>>
                &nbsp;Send email when threats are detected during a scan</label>
            </div>
            <div class="sh-field">
                <label for="shield_alert_email">Alert Email</label>
                <input type="email" id="shield_alert_email" name="shield_alert_email" value="<?php echo esc_attr( $settings['alert_email'] ); ?>">
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
        <?php if ( $msg === 'invalid' )     echo '<div class="sh-err">⚠ Invalid license key. Please check and try again.</div>'; ?>

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
        <div class="sh-card">
            <h2>🔑 Activate License</h2>
            <p style="font-size:13px;color:#555;">Enter your license key to enable auto-updates and full features. Purchase at <a href="https://nextnovatechnologies.com" target="_blank">nextnovatechnologies.com</a>.</p>
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
        <div class="sh-card">
            <h2>✔ License Active</h2>
            <p style="font-size:13px;">Your license is valid and active on this domain.</p>
            <form method="post">
                <?php shield_nonce_field(); ?>
                <input type="hidden" name="shield_license_action" value="deactivate">
                <button type="submit" class="sh-btn sh-btn-grey" onclick="return confirm('Deactivate on this domain?')">Deactivate</button>
            </form>
        </div>
        <?php endif; ?>

        <div class="sh-card">
            <h2>📦 What Your License Includes</h2>
            <table class="sh-tbl"><tbody>
                <tr><td>✔ Deep malware scanner (9 steps, timeout-proof)</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ One-click threat removal</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Auto-updates via GitHub</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Custom login URL hardening</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Email threat alerts</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Support from Next Nova Technologies</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
            </tbody></table>
        </div>
        </div>
        <?php
    }
}
