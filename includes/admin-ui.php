<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Shield_Admin_UI {

    public static function init() {
        add_action( 'admin_menu',    array( __CLASS__, 'register_menu' ) );
        add_action( 'admin_head',    array( __CLASS__, 'styles' ) );
        add_action( 'admin_init',    array( __CLASS__, 'handle_actions' ) );
        add_action( 'admin_notices', array( __CLASS__, 'update_notice' ) );
        add_action( 'wp_ajax_shield_scan_step',      array( __CLASS__, 'ajax_scan_step' ) );
        add_action( 'wp_ajax_shield_dismiss_threat', array( __CLASS__, 'ajax_dismiss_threat' ) );
    }

    public static function register_menu() {
        add_menu_page( 'Shield Security', '🛡 Shield', 'manage_options', 'shield-security', array( __CLASS__, 'page_dashboard' ), 'dashicons-shield-alt', 80 );
        add_submenu_page( 'shield-security', 'Dashboard',      'Dashboard',      'manage_options', 'shield-security', array( __CLASS__, 'page_dashboard' ) );
        add_submenu_page( 'shield-security', 'Scanner',        'Scanner',        'manage_options', 'shield-scanner',  array( __CLASS__, 'page_scanner' ) );
        add_submenu_page( 'shield-security', 'Login Security', 'Login Security', 'manage_options', 'shield-login',    array( __CLASS__, 'page_login' ) );
        add_submenu_page( 'shield-security', 'Settings',       'Settings',       'manage_options', 'shield-settings', array( __CLASS__, 'page_settings' ) );
        add_submenu_page( 'shield-security', 'License',        'License',        'manage_options', 'shield-license',  array( __CLASS__, 'page_license' ) );
    }

    // ── AJAX handlers ─────────────────────────────────────────────────

    public static function ajax_scan_step() {
        shield_admin_only();
        check_ajax_referer( 'shield_ajax', 'nonce' );
        $step = sanitize_key( $_POST['step'] ?? '' );
        if ( ! array_key_exists( $step, Shield_Scanner::get_steps() ) ) {
            wp_send_json_error( array( 'message' => 'Unknown step.' ) );
        }
        wp_send_json_success( Shield_Scanner::run_step( $step ) );
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
            wp_send_json_success( array( 'remaining' => $scan['threat_count'] ) );
        }
        wp_send_json_error( array( 'message' => 'Threat not found.' ) );
    }

    // ── Form actions ──────────────────────────────────────────────────

    public static function handle_actions() {
        if ( empty( $_POST['shield_action'] ) ) return;
        shield_admin_only();
        if ( ! shield_verify_nonce() ) wp_die( 'Bad nonce' );

        $action = sanitize_key( $_POST['shield_action'] );

        if ( $action === 'save_settings' ) {
            Shield_Settings::handle_post();
            return;
        }

        if ( $action === 'clean_selected' ) {
            $scan    = Shield_Scanner::get_last_scan();
            $indices = isset( $_POST['threat_indices'] ) ? array_map( 'intval', (array) $_POST['threat_indices'] ) : array();
            if ( $scan && ! empty( $indices ) && ! empty( $scan['threats'] ) ) {
                // Process in reverse order so indices stay valid after splicing
                rsort( $indices );
                foreach ( $indices as $idx ) {
                    if ( isset( $scan['threats'][ $idx ] ) ) {
                        $result = Shield_Cleanup::remove_threat( $scan['threats'][ $idx ] );
                        shield_log( $result['message'], $result['ok'] ? 'info' : 'warn' );
                        array_splice( $scan['threats'], $idx, 1 );
                    }
                }
                $scan['threat_count'] = count( $scan['threats'] );
                update_option( 'shield_last_scan', $scan );
            }
            wp_redirect( add_query_arg( array( 'page' => 'shield-scanner', 'clean' => 'done' ), admin_url( 'admin.php' ) ) );
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

        if ( $action === 'dismiss_selected' ) {
            $scan    = Shield_Scanner::get_last_scan();
            $indices = isset( $_POST['threat_indices'] ) ? array_map( 'intval', (array) $_POST['threat_indices'] ) : array();
            if ( $scan && ! empty( $indices ) ) {
                rsort( $indices );
                foreach ( $indices as $idx ) {
                    if ( isset( $scan['threats'][ $idx ] ) ) array_splice( $scan['threats'], $idx, 1 );
                }
                $scan['threat_count'] = count( $scan['threats'] );
                update_option( 'shield_last_scan', $scan );
            }
            wp_redirect( add_query_arg( array( 'page' => 'shield-scanner', 'clean' => 'dismissed' ), admin_url( 'admin.php' ) ) );
            exit;
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

    // ── Styles + JS ───────────────────────────────────────────────────

    public static function styles() {
        $screen = get_current_screen();
        if ( ! $screen || strpos( $screen->id, 'shield' ) === false ) return;
        $ajax_nonce = wp_create_nonce( 'shield_ajax' );
        ?>
        <style>
        #shield-wrap{max-width:960px;margin:30px auto;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
        .sh-card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:24px;margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
        .sh-card h2{margin-top:0;font-size:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
        .sh-badge{display:inline-block;padding:3px 11px;border-radius:20px;font-size:12px;font-weight:700}
        .sh-red{background:#fdecea;color:#c0392b} .sh-ok{background:#d4edda;color:#155724}
        .sh-warn{background:#fff3cd;color:#856404} .sh-info{background:#d1ecf1;color:#0c5460}
        .sh-grey{background:#f0f0f0;color:#555}
        .sh-btn{display:inline-block;padding:9px 18px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;border:none;text-decoration:none}
        .sh-btn:hover{opacity:.88} .sh-btn:disabled{opacity:.45;cursor:not-allowed}
        .sh-btn-red{background:#e74c3c;color:#fff} .sh-btn-blue{background:#2271b1;color:#fff}
        .sh-btn-green{background:#27ae60;color:#fff} .sh-btn-grey{background:#f0f0f0;color:#333;border:1px solid #ccc}
        .sh-btn-orange{background:#e67e22;color:#fff}
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
        .sh-field input[type=text],.sh-field input[type=email],.sh-field textarea{width:100%;max-width:420px;padding:8px 10px;border:1px solid #ccc;border-radius:5px;font-size:13px;box-sizing:border-box}
        .sh-field textarea{resize:vertical;max-width:100%;font-family:monospace}
        .sh-saved{background:#d4edda;color:#155724;padding:10px 16px;border-radius:6px;margin-bottom:20px;font-size:13px;font-weight:600}
        .sh-err-box{background:#fdecea;color:#c0392b;padding:10px 16px;border-radius:6px;margin-bottom:20px;font-size:13px}
        .sh-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px;align-items:center}
        /* Step progress */
        .sh-steps{list-style:none;margin:0;padding:0}
        .sh-step{display:flex;align-items:center;gap:14px;padding:10px 14px;border-radius:7px;margin-bottom:5px;font-size:13px;background:#f9f9f9;border:1px solid #eee;transition:background .2s}
        .sh-step.step-waiting{color:#aaa}
        .sh-step.step-running{background:#f0f6ff;border-color:#b8d4f5;color:#1a4a8a;font-weight:600}
        .sh-step.step-done{background:#f0fff4;border-color:#b7e4c7;color:#155724}
        .sh-step.step-error{background:#fff0f0;border-color:#f5c6cb;color:#c0392b}
        .sh-step-icon{width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0}
        .step-waiting .sh-step-icon{background:#e5e5e5;color:#aaa}
        .step-running .sh-step-icon{background:#2271b1;color:#fff}
        .step-done    .sh-step-icon{background:#27ae60;color:#fff}
        .step-error   .sh-step-icon{background:#e74c3c;color:#fff}
        .sh-step-label{flex:1}
        .sh-step-meta{font-size:11px;opacity:.7;white-space:nowrap}
        .sh-step-threat{font-size:11px;font-weight:700;color:#c0392b;background:#fdecea;padding:1px 8px;border-radius:10px;margin-right:6px}
        .sh-spin{display:inline-block;width:11px;height:11px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:sh-spin .6s linear infinite}
        @keyframes sh-spin{to{transform:rotate(360deg)}}
        .sh-overall-bar{height:5px;background:#e0e0e0;border-radius:3px;overflow:hidden;margin:14px 0 4px}
        .sh-overall-fill{height:100%;background:linear-gradient(90deg,#2271b1,#27ae60);border-radius:3px;transition:width .4s ease;width:0}
        .sh-scan-summary{font-size:13px;color:#555;min-height:18px}
        /* Threat table */
        .sh-threat-row-critical{background:#fff8f8}
        .sh-threat-row-warning{background:#fffdf0}
        .sh-threat-check{width:32px;text-align:center}
        .sh-sel-bar{background:#f0f6ff;border:1px solid #b8d4f5;border-radius:6px;padding:10px 16px;margin-bottom:12px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:13px}
        .sh-sel-count{font-weight:600;color:#2271b1}
        .sh-lic-box{border:2px solid;border-radius:8px;padding:20px;text-align:center;margin-bottom:24px}
        code{background:#f4f4f4;padding:1px 5px;border-radius:3px;font-size:12px}
        @media(max-width:700px){.sh-grid{grid-template-columns:1fr}}
        </style>
        <script>
        (function(){
        var shNonce = '<?php echo esc_js( $ajax_nonce ); ?>';
        var shAjax  = '<?php echo esc_js( admin_url( "admin-ajax.php" ) ); ?>';
        var shSteps = <?php echo wp_json_encode( array_keys( Shield_Scanner::get_steps() ) ); ?>;
        var shLabels= <?php echo wp_json_encode( Shield_Scanner::get_steps() ); ?>;
        var scanning= false, stepsDone=0, totalThreats=0, totalFiles=0;

        function el(id){ return document.getElementById(id); }

        function setStep(step, state, meta, threats){
            var row   = el('sh-step-' + step);
            var icon  = el('sh-icon-' + step);
            var metaEl= el('sh-meta-' + step);
            var thrEl = el('sh-thr-'  + step);
            if (!row) return;
            row.className = 'sh-step step-' + state;
            var icons = {waiting:'○', running:'<span class="sh-spin"></span>', done:'✔', error:'✘'};
            if (icon) icon.innerHTML = icons[state] || '○';
            if (meta   && metaEl) metaEl.textContent = meta;
            if (threats && thrEl && threats > 0){
                thrEl.textContent = threats + ' threat' + (threats>1?'s':'') + ' found';
                thrEl.style.display = 'inline-block';
            }
        }

        function updateBar(done, total){
            var fill = el('sh-overall-fill');
            if (fill) fill.style.width = Math.round((done/total)*100) + '%';
            var sum = el('sh-scan-summary');
            if (sum) sum.textContent = done + ' of ' + total + ' steps' +
                (totalThreats > 0 ? ' · ' + totalThreats + ' threat(s) found' : '') +
                (totalFiles   > 0 ? ' · ' + totalFiles + ' file(s) scanned' : '');
        }

        function runStep(idx){
            if (idx >= shSteps.length){ finish(); return; }
            var step = shSteps[idx];
            setStep(step, 'running', 'Scanning…', 0);
            updateBar(idx, shSteps.length);
            fetch(shAjax, {
                method:'POST',
                headers:{'Content-Type':'application/x-www-form-urlencoded'},
                body:'action=shield_scan_step&nonce=' + encodeURIComponent(shNonce) + '&step=' + encodeURIComponent(step)
            })
            .then(function(r){ return r.json(); })
            .then(function(d){
                if (d.success){
                    stepsDone++;
                    totalThreats += (d.data.threats_found || 0);
                    totalFiles   += (d.data.files_scanned || 0);
                    var meta = (d.data.files_scanned ? d.data.files_scanned + ' file(s) · ' : '') + (d.data.time ? d.data.time + 's' : '');
                    setStep(step, 'done', meta, d.data.threats_found || 0);
                    updateBar(stepsDone, shSteps.length);
                    if (d.data.final){ finish(d.data.threat_count); }
                    else { runStep(idx + 1); }
                } else {
                    setStep(step, 'error', 'Failed', 0);
                    showScanError('Step "' + shLabels[step] + '" failed. Try again.');
                    enableBtn();
                }
            })
            .catch(function(e){
                setStep(step, 'error', 'Network error', 0);
                showScanError('Network error: ' + e.message);
                enableBtn();
            });
        }

        function finish(tc){
            var fill = el('sh-overall-fill');
            if (fill){ fill.style.width='100%'; fill.style.background='#27ae60'; }
            var sum = el('sh-scan-summary');
            var count = typeof tc !== 'undefined' ? tc : totalThreats;
            if (sum){
                sum.textContent = 'Scan complete · ' + totalFiles + ' file(s) · ' + (count > 0 ? count + ' threat(s) found' : 'No threats ✔');
                sum.style.color = count > 0 ? '#c0392b' : '#155724';
            }
            setTimeout(function(){
                window.location.href = window.location.href.split('?')[0] + '?page=shield-scanner&scanned=1&threats=' + count;
            }, 900);
        }

        function showScanError(msg){
            var e = el('sh-scan-error');
            if (e){ e.textContent = msg; e.style.display='block'; }
        }

        function enableBtn(){
            var btn = el('sh-run-btn');
            if (btn){ btn.disabled=false; btn.textContent='🔍 Run Scan Again'; }
            scanning = false;
        }

        window.shieldStartScan = function(btn){
            if (scanning) return;
            scanning=true; stepsDone=0; totalThreats=0; totalFiles=0;
            btn.disabled=true; btn.textContent='Scanning…';
            for (var i=0; i<shSteps.length; i++){
                setStep(shSteps[i], 'waiting', '', 0);
                var te = el('sh-thr-' + shSteps[i]);
                if (te) te.style.display='none';
            }
            var fill = el('sh-overall-fill');
            if (fill){ fill.style.width='0'; fill.style.background='linear-gradient(90deg,#2271b1,#27ae60)'; }
            var err = el('sh-scan-error');
            if (err) err.style.display='none';
            runStep(0);
        };

        // Dismiss single threat via AJAX (no page reload, no nonce issue)
        window.shieldDismiss = function(btn, idx){
            if (!confirm('Dismiss this threat from the list? It will not be cleaned.')) return;
            btn.disabled=true; btn.textContent='…';
            fetch(shAjax, {
                method:'POST',
                headers:{'Content-Type':'application/x-www-form-urlencoded'},
                body:'action=shield_dismiss_threat&nonce=' + encodeURIComponent(shNonce) + '&threat_index=' + idx
            })
            .then(function(r){ return r.json(); })
            .then(function(d){
                if (d.success){
                    var row = btn.closest('tr');
                    if (row){ row.style.opacity='0'; row.style.transition='opacity .3s'; setTimeout(function(){ row.remove(); updateSelCount(); }, 320); }
                } else { btn.disabled=false; btn.textContent='Dismiss'; alert('Could not dismiss — try again.'); }
            })
            .catch(function(){ btn.disabled=false; btn.textContent='Dismiss'; });
        };

        // Checkbox selection helpers
        window.shieldToggleAll = function(master){
            var boxes = document.querySelectorAll('.sh-threat-cb');
            for (var i=0; i<boxes.length; i++) boxes[i].checked = master.checked;
            updateSelCount();
        };

        window.updateSelCount = function(){
            var boxes   = document.querySelectorAll('.sh-threat-cb');
            var checked = document.querySelectorAll('.sh-threat-cb:checked');
            var bar     = el('sh-sel-bar');
            var cnt     = el('sh-sel-count');
            if (bar) bar.style.display = checked.length > 0 ? 'flex' : 'none';
            if (cnt) cnt.textContent   = checked.length + ' selected';
            // Put selected indices into hidden inputs
            var form = document.getElementById('sh-bulk-form');
            if (!form) return;
            var old = form.querySelectorAll('input[name="threat_indices[]"]');
            for (var j=0; j<old.length; j++) old[j].remove();
            for (var k=0; k<checked.length; k++){
                var inp = document.createElement('input');
                inp.type='hidden'; inp.name='threat_indices[]'; inp.value=checked[k].value;
                form.appendChild(inp);
            }
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
        $threats = $scan ? intval( $scan['threat_count'] ) : null;
        $release = Shield_Updater::get_latest_release();
        $latest  = $release ? ltrim( $release['tag_name'], 'v' ) : SHIELD_VERSION;
        $update  = version_compare( $latest, SHIELD_VERSION, '>' );
        ?>
        <div id="shield-wrap">
        <h1>🛡 Shield Security <span style="font-size:13px;font-weight:400;color:#888;">v<?php echo esc_html( SHIELD_VERSION ); ?></span></h1>

        <div class="sh-grid">
            <div class="sh-stat <?php echo ( $threats === null ) ? '' : ( $threats > 0 ? 'sh-red' : 'sh-ok' ); ?>">
                <div class="num"><?php echo $threats === null ? '—' : $threats; ?></div>
                <div class="lbl">Threats Detected</div>
            </div>
            <a href="<?php echo admin_url( 'admin.php?page=shield-license' ); ?>"
               class="sh-stat" style="border-color:<?php echo esc_attr( $lic['color'] ); ?>;text-decoration:none;display:block;">
                <div class="num" style="font-size:18px;color:<?php echo esc_attr( $lic['color'] ); ?>"><?php echo esc_html( $lic['label'] ); ?></div>
                <div class="lbl" style="color:#666;">License Status ↗</div>
            </a>
            <div class="sh-stat <?php echo $update ? 'sh-warn' : 'sh-ok'; ?>">
                <div class="num" style="font-size:16px;"><?php echo $update ? 'v' . esc_html( $latest ) . ' ↑' : 'Up to date'; ?></div>
                <div class="lbl">Plugin Version</div>
            </div>
        </div>

        <div class="sh-card">
            <h2>⚡ Quick Actions</h2>
            <div class="sh-actions">
                <a href="<?php echo admin_url( 'admin.php?page=shield-scanner' ); ?>"  class="sh-btn sh-btn-blue">🔍 Scanner</a>
                <a href="<?php echo admin_url( 'admin.php?page=shield-login' ); ?>"    class="sh-btn sh-btn-blue">🔑 Login Security</a>
                <a href="<?php echo admin_url( 'admin.php?page=shield-settings' ); ?>" class="sh-btn sh-btn-grey">⚙ Settings</a>
                <?php if ( $update ) : ?>
                <a href="<?php echo admin_url( 'update-core.php' ); ?>" class="sh-btn sh-btn-green">⬆ Update to v<?php echo esc_html( $latest ); ?></a>
                <?php endif; ?>
            </div>
        </div>

        <div class="sh-card">
            <h2>📋 Recent Activity</h2>
            <?php $logs = get_option( 'shield_scan_log', array() ); ?>
            <?php if ( empty( $logs ) ) : ?>
                <p style="color:#888;">No activity yet. Run a scan to get started.</p>
            <?php else : ?>
            <table class="sh-tbl"><thead><tr><th>Time</th><th>Level</th><th>Message</th></tr></thead><tbody>
            <?php foreach ( array_slice( $logs, 0, 15 ) as $entry ) : ?>
                <tr>
                    <td style="white-space:nowrap;color:#888;"><?php echo esc_html( $entry['time'] ); ?></td>
                    <td><span class="sh-badge <?php echo $entry['level']==='warn'?'sh-warn':'sh-info'; ?>"><?php echo esc_html( strtoupper( $entry['level'] ) ); ?></span></td>
                    <td><?php echo esc_html( $entry['message'] ); ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody></table>
            <?php endif; ?>
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
        $threats = $scan ? $scan['threats'] : array();
        ?>
        <div id="shield-wrap">
        <h1>🔍 Malware Scanner</h1>

        <?php if ( $clean === 'all_done' )  echo '<div class="sh-saved">✔ All selected threats cleaned.</div>'; ?>
        <?php if ( $clean === 'done' )       echo '<div class="sh-saved">✔ Selected threats processed.</div>'; ?>
        <?php if ( $clean === 'dismissed' )  echo '<div class="sh-saved" style="background:#d1ecf1;color:#0c5460;">Threats dismissed from list.</div>'; ?>

        <!-- Run Scan -->
        <div class="sh-card">
            <h2>▶ Run a Full Scan</h2>
            <p style="font-size:13px;color:#555;margin-bottom:14px;">
                Runs as <strong><?php echo count( $steps ); ?> separate steps</strong> — each completes independently so no server timeout can stop it.
                Includes a dedicated step for fake JPEG credential log files.
            </p>
            <div class="sh-actions">
                <button id="sh-run-btn" type="button" class="sh-btn sh-btn-blue" onclick="shieldStartScan(this)">🔍 Run Full Scan</button>
            </div>
            <div id="sh-scan-error" class="sh-err-box" style="display:none;margin-top:12px;"></div>
            <div class="sh-overall-bar"><div id="sh-overall-fill" class="sh-overall-fill"></div></div>
            <div id="sh-scan-summary" class="sh-scan-summary"></div>
            <ul class="sh-steps" style="margin-top:18px;">
                <?php foreach ( $steps as $key => $label ) : ?>
                <li id="sh-step-<?php echo esc_attr( $key ); ?>" class="sh-step step-waiting">
                    <span id="sh-icon-<?php echo esc_attr( $key ); ?>" class="sh-step-icon">○</span>
                    <span class="sh-step-label"><?php echo esc_html( $label ); ?></span>
                    <span id="sh-thr-<?php  echo esc_attr( $key ); ?>" class="sh-step-threat" style="display:none;"></span>
                    <span id="sh-meta-<?php echo esc_attr( $key ); ?>" class="sh-step-meta"></span>
                </li>
                <?php endforeach; ?>
            </ul>
            <?php if ( $scan ) : ?>
            <p style="font-size:12px;color:#aaa;margin-top:14px;margin-bottom:0;">
                Last scan: <?php echo esc_html( $scan['completed_at'] ); ?>
                &nbsp;·&nbsp; <?php echo number_format( $scan['files_scanned'] ); ?> files
                &nbsp;·&nbsp; <?php echo number_format( $scan['db_rows_scanned'] ); ?> DB rows
            </p>
            <?php endif; ?>
        </div>

        <!-- Threat Results -->
        <div class="sh-card">
            <h2>
                ⚠ Scan Results
                <?php if ( ! empty( $threats ) ) : ?>
                    <span class="sh-badge sh-red"><?php echo count( $threats ); ?> threat(s)</span>
                <?php elseif ( $scan ) : ?>
                    <span class="sh-badge sh-ok">✔ Clean</span>
                <?php endif; ?>
            </h2>

            <?php if ( empty( $threats ) ) : ?>
                <p style="color:<?php echo $scan ? '#155724' : '#888'; ?>;">
                    <?php echo $scan ? '✔ No threats in last scan.' : 'Run a scan above to check your site.'; ?>
                </p>
            <?php else : ?>

            <!-- Selection action bar (hidden until something is checked) -->
            <div id="sh-sel-bar" class="sh-sel-bar" style="display:none;">
                <span id="sh-sel-count" class="sh-sel-count">0 selected</span>
                <button type="submit" form="sh-bulk-form" name="shield_action" value="clean_selected"
                    class="sh-btn sh-btn-red" style="padding:5px 14px;"
                    onclick="return confirm('Remove all selected threats?')">🗑 Remove Selected</button>
                <button type="submit" form="sh-bulk-form" name="shield_action" value="dismiss_selected"
                    class="sh-btn sh-btn-grey" style="padding:5px 14px;"
                    onclick="return confirm('Dismiss selected threats from the list?')">Dismiss Selected</button>
            </div>

            <p style="font-size:13px;color:#666;margin-bottom:12px;">
                Use checkboxes to select threats, then use <strong>Remove Selected</strong> or <strong>Dismiss Selected</strong>.
                You can also act on individual threats using the row buttons.
                To permanently exclude a file from future scans go to <a href="<?php echo admin_url('admin.php?page=shield-settings'); ?>">Settings → Excluded Paths</a>.
            </p>

            <form id="sh-bulk-form" method="post">
                <?php shield_nonce_field(); ?>
                <!-- shield_action is set by whichever submit button is clicked -->

                <table class="sh-tbl">
                    <thead>
                        <tr>
                            <th class="sh-threat-check"><input type="checkbox" onclick="shieldToggleAll(this)" title="Select all"></th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Location</th>
                            <th>Description</th>
                            <th style="width:160px;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ( $threats as $i => $threat ) :
                        $sev = isset( $threat['severity'] ) ? $threat['severity'] : 'warning';
                    ?>
                    <tr class="sh-threat-row-<?php echo esc_attr( $sev ); ?>">
                        <td class="sh-threat-check">
                            <input type="checkbox" class="sh-threat-cb" value="<?php echo intval( $i ); ?>" onchange="updateSelCount()">
                        </td>
                        <td><code><?php echo esc_html( $threat['type'] ); ?></code></td>
                        <td>
                            <?php if ( $sev === 'critical' ) : ?>
                                <span class="sh-badge sh-red">Critical</span>
                            <?php else : ?>
                                <span class="sh-badge sh-warn">Warning</span>
                            <?php endif; ?>
                        </td>
                        <td style="font-family:monospace;font-size:12px;"><?php echo esc_html( $threat['location'] ); ?></td>
                        <td style="font-size:12px;"><?php echo esc_html( $threat['description'] ); ?></td>
                        <td>
                            <!-- Remove single -->
                            <form method="post" style="display:inline;">
                                <?php shield_nonce_field(); ?>
                                <input type="hidden" name="shield_action"       value="clean_selected">
                                <input type="hidden" name="threat_indices[]"    value="<?php echo intval( $i ); ?>">
                                <button type="submit" class="sh-btn sh-btn-red" style="padding:3px 10px;font-size:12px;"
                                    onclick="return confirm('Remove this threat?')">Remove</button>
                            </form>
                            <!-- Dismiss single via AJAX -->
                            <button type="button" class="sh-btn sh-btn-grey" style="padding:3px 10px;font-size:12px;margin-left:4px;"
                                onclick="shieldDismiss(this, <?php echo intval( $i ); ?>)">Dismiss</button>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </form>

            <div class="sh-actions" style="margin-top:16px;">
                <form method="post" style="display:inline;">
                    <?php shield_nonce_field(); ?>
                    <input type="hidden" name="shield_action" value="clean_all">
                    <button type="submit" class="sh-btn sh-btn-red"
                        onclick="return confirm('Remove ALL <?php echo count( $threats ); ?> threat(s)? This cannot be undone.')">
                        🧹 Remove All Threats
                    </button>
                </form>
                <a href="<?php echo admin_url( 'admin.php?page=shield-settings' ); ?>"
                   class="sh-btn sh-btn-grey">⚙ Manage Excluded Paths</a>
            </div>

            <?php endif; ?>
        </div>
        </div>
        <?php
    }

    // ═══════════════════════════════════════════════════════════════════
    // LOGIN SECURITY
    // ═══════════════════════════════════════════════════════════════════
    public static function page_login() {
        $settings = shield_get_settings();
        $saved    = isset( $_GET['shield_saved'] );
        ?>
        <div id="shield-wrap">
        <h1>🔑 Login Security</h1>
        <?php if ( $saved ) : ?>
        <div class="sh-saved">✔ Saved. If the custom login URL doesn't work go to Settings → Permalinks → Save.</div>
        <?php endif; ?>

        <div class="sh-card" style="border-left:4px solid #e74c3c;">
            <h2>⚠ Before Enabling</h2>
            <p style="font-size:13px;">Bookmark your new login URL before saving: <code><?php echo esc_html( home_url( '/' . ( $settings['login_slug'] ?: 'site-login' ) ) ); ?></code></p>
        </div>

        <form method="post">
        <?php shield_nonce_field(); ?>
        <input type="hidden" name="shield_action" value="save_settings">

        <div class="sh-card">
            <h2>🔒 Custom Login URL</h2>
            <div class="sh-field">
                <label>Login Slug</label>
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                    <span style="color:#888;font-size:13px;"><?php echo esc_html( trailingslashit( home_url() ) ); ?></span>
                    <input type="text" name="shield_login_slug" value="<?php echo esc_attr( $settings['login_slug'] ); ?>" placeholder="site-login" style="max-width:160px;">
                </div>
                <div class="desc">Letters, numbers, hyphens only. Replaces <code>/wp-login.php</code>.</div>
            </div>
            <div class="sh-field">
                <label><input type="checkbox" name="shield_hide_login" value="1" <?php checked( $settings['hide_login'], '1' ); ?>>
                &nbsp;Enable login URL hardening</label>
                <div class="desc">Blocks direct access to <code>/wp-login.php</code> and <code>/wp-admin</code> for non-logged-in visitors.</div>
            </div>
        </div>

        <div class="sh-card">
            <h2>🤖 Bot Protection</h2>
            <div class="sh-field">
                <label><input type="checkbox" name="shield_bot_redirect_404" value="1" <?php checked( $settings['bot_redirect_404'], '1' ); ?>>
                &nbsp;Return 404 to bots accessing <code>/wp-login.php</code> or <code>/wp-admin</code></label>
                <div class="desc">Bots and scanners see a 404. Human visitors are redirected to your custom login URL.</div>
            </div>
        </div>

        <button type="submit" class="sh-btn sh-btn-blue">💾 Save</button>
        </form>

        <div class="sh-card" style="margin-top:20px;">
            <h2>ℹ Status</h2>
            <table class="sh-tbl"><tbody>
                <tr><td>Login hardening</td><td><?php echo $settings['hide_login']==='1'?'<span class="sh-badge sh-ok">Enabled</span>':'<span class="sh-badge sh-grey">Disabled</span>'; ?></td></tr>
                <tr><td>Custom login URL</td><td><?php echo $settings['login_slug']?'<code>'.esc_html(home_url('/'.$settings['login_slug'])).'</code>':'<span style="color:#888">Not set</span>'; ?></td></tr>
                <tr><td>Bot 404</td><td><?php echo $settings['bot_redirect_404']==='1'?'<span class="sh-badge sh-ok">Enabled</span>':'<span class="sh-badge sh-grey">Disabled</span>'; ?></td></tr>
            </tbody></table>
        </div>
        </div>
        <?php
    }

    // ═══════════════════════════════════════════════════════════════════
    // SETTINGS
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
                &nbsp;Enable automatic updates from GitHub (requires valid license)</label>
            </div>
        </div>

        <div class="sh-card">
            <h2>📧 Email Alerts</h2>
            <div class="sh-field">
                <label><input type="checkbox" name="shield_email_alerts" value="1" <?php checked( $settings['email_alerts'], '1' ); ?>>
                &nbsp;Email me when threats are detected during a scan</label>
            </div>
            <div class="sh-field">
                <label>Alert Email Address</label>
                <input type="email" name="shield_alert_email" value="<?php echo esc_attr( $settings['alert_email'] ); ?>">
            </div>
        </div>

        <div class="sh-card">
            <h2>🚫 Excluded Paths</h2>
            <p style="font-size:13px;color:#555;margin-bottom:12px;">
                Files or folders listed here will be skipped during scans. Use this to prevent false positives.
                The plugin's own folder is always excluded automatically — you don't need to add it.
            </p>
            <div class="sh-field">
                <label>Paths to exclude <span style="font-weight:400;color:#888;">(one per line, relative to WordPress root or absolute)</span></label>
                <textarea name="shield_excluded_paths" rows="6" style="max-width:100%;font-family:monospace;font-size:12px;"><?php echo esc_textarea( $settings['excluded_paths'] ); ?></textarea>
                <div class="desc">
                    Examples:<br>
                    <code>wp-content/plugins/my-other-plugin</code><br>
                    <code>wp-content/themes/my-theme/custom.php</code>
                </div>
            </div>
            <div style="background:#f0fff4;border:1px solid #b7e4c7;border-radius:6px;padding:10px 14px;font-size:13px;color:#155724;">
                ✔ This plugin's own directory (<code><?php echo esc_html( str_replace( ABSPATH, '', SHIELD_DIR ) ); ?></code>) is always excluded automatically.
            </div>
        </div>

        <button type="submit" class="sh-btn sh-btn-blue">💾 Save Settings</button>
        </form>
        </div>
        <?php
    }

    // ═══════════════════════════════════════════════════════════════════
    // LICENSE
    // ═══════════════════════════════════════════════════════════════════
    public static function page_license() {
        $lic_data = get_option( SHIELD_LIC_OPT, array() );
        $is_valid = Shield_License::is_valid();
        $status   = Shield_License::get_status_label();
        $msg      = isset( $_GET['lic_msg'] ) ? sanitize_key( $_GET['lic_msg'] ) : '';
        ?>
        <div id="shield-wrap">
        <h1>🔐 License</h1>
        <?php if ( $msg === 'activated' )   echo '<div class="sh-saved">✔ License activated.</div>'; ?>
        <?php if ( $msg === 'deactivated' ) echo '<div class="sh-saved" style="background:#d1ecf1;color:#0c5460;">License deactivated.</div>'; ?>
        <?php if ( $msg === 'invalid' )     echo '<div class="sh-err-box">⚠ Invalid license key — check and try again.</div>'; ?>

        <div class="sh-lic-box" style="border-color:<?php echo esc_attr( $status['color'] ); ?>">
            <div style="font-size:26px;font-weight:700;color:<?php echo esc_attr( $status['color'] ); ?>"><?php echo esc_html( $status['label'] ); ?></div>
            <?php if ( ! empty( $lic_data['key'] ) ) : ?>
            <div style="margin-top:8px;font-size:13px;color:#888;">
                Key: <code><?php echo esc_html( substr( $lic_data['key'], 0, 8 ) . str_repeat( '•', 16 ) ); ?></code>
                &nbsp;·&nbsp; Domain: <code><?php echo esc_html( isset( $lic_data['domain'] ) ? $lic_data['domain'] : home_url() ); ?></code>
            </div>
            <?php endif; ?>
        </div>

        <?php if ( ! $is_valid ) : ?>
        <div class="sh-card">
            <h2>🔑 Activate License</h2>
            <p style="font-size:13px;color:#555;">Purchase at <a href="https://nextnovatechnologies.com" target="_blank">nextnovatechnologies.com</a>.</p>
            <form method="post">
                <?php shield_nonce_field(); ?>
                <input type="hidden" name="shield_license_action" value="activate">
                <div class="sh-field">
                    <label>License Key</label>
                    <input type="text" name="shield_license_key" placeholder="XXXX-XXXX-XXXX-XXXX" style="font-family:monospace;">
                </div>
                <button type="submit" class="sh-btn sh-btn-blue">Activate</button>
            </form>
        </div>
        <?php else : ?>
        <div class="sh-card">
            <h2>✔ License Active</h2>
            <p style="font-size:13px;">Your license is valid on this domain.</p>
            <form method="post">
                <?php shield_nonce_field(); ?>
                <input type="hidden" name="shield_license_action" value="deactivate">
                <button type="submit" class="sh-btn sh-btn-grey" onclick="return confirm('Deactivate on this domain?')">Deactivate</button>
            </form>
        </div>
        <?php endif; ?>

        <div class="sh-card">
            <h2>📦 What's Included</h2>
            <table class="sh-tbl"><tbody>
                <tr><td>✔ Deep malware scanner (9 steps, timeout-proof)</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Fake JPEG credential log detection &amp; removal</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Checkbox selection — remove or dismiss specific threats</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Excluded paths — prevent false positives</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ One-click threat removal</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Auto-updates via GitHub</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Custom login URL hardening</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
                <tr><td>✔ Email threat alerts</td><td><span class="sh-badge sh-ok">Included</span></td></tr>
            </tbody></table>
        </div>
        </div>
        <?php
    }
}
