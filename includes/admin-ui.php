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
        add_submenu_page( 'shield-security', '🔒 Lockdown',   '🔒 Lockdown',   'manage_options', 'shield-lockdown', array( __CLASS__, 'page_lockdown' ) );
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
        /* ── NovaShield Design System ─────────────────────────────────── */
        :root{
            --ns-bg:#f0f4f8;--ns-surface:#fff;--ns-border:#e2e8f0;
            --ns-blue:#2563eb;--ns-blue-lt:#eff6ff;--ns-blue-dk:#1e40af;
            --ns-green:#16a34a;--ns-green-lt:#f0fdf4;
            --ns-red:#dc2626;--ns-red-lt:#fef2f2;
            --ns-orange:#d97706;--ns-orange-lt:#fffbeb;
            --ns-grey:#64748b;--ns-text:#0f172a;--ns-muted:#94a3b8;
            --ns-radius:10px;--ns-shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.06);
            --ns-shadow-md:0 4px 6px rgba(0,0,0,.07),0 2px 4px rgba(0,0,0,.06);
        }
        #shield-wrap{max-width:980px;margin:24px auto;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ns-text)}
        #shield-wrap h1{font-size:22px;font-weight:700;margin:0 0 20px;display:flex;align-items:center;gap:10px;color:var(--ns-text)}
        #shield-wrap h1 .ns-ver{font-size:12px;font-weight:400;color:var(--ns-muted);background:var(--ns-border);padding:2px 8px;border-radius:20px}
        /* ── Cards ── */
        .sh-card{background:var(--ns-surface);border:1px solid var(--ns-border);border-radius:var(--ns-radius);padding:22px 24px;margin-bottom:20px;box-shadow:var(--ns-shadow)}
        .sh-card h2{margin:0 0 16px;font-size:14px;font-weight:600;color:var(--ns-text);display:flex;align-items:center;gap:8px;flex-wrap:wrap;text-transform:uppercase;letter-spacing:.4px}
        .sh-card-row{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}
        @media(max-width:720px){.sh-card-row{grid-template-columns:1fr}}
        /* ── Status tiles ── */
        .ns-tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
        @media(max-width:800px){.ns-tiles{grid-template-columns:repeat(2,1fr)}}
        @media(max-width:480px){.ns-tiles{grid-template-columns:1fr}}
        .ns-tile{background:var(--ns-surface);border:1px solid var(--ns-border);border-radius:var(--ns-radius);padding:18px 16px 14px;box-shadow:var(--ns-shadow);position:relative;text-decoration:none;display:block;transition:box-shadow .15s,transform .15s}
        .ns-tile:hover{box-shadow:var(--ns-shadow-md);transform:translateY(-1px)}
        .ns-tile-icon{font-size:18px;line-height:1}
        .ns-tile-top{display:flex;align-items:center;gap:8px;margin-bottom:4px}
        .ns-tile-val{font-size:20px;font-weight:700;line-height:1.1;color:var(--ns-text)}
        .ns-tile-lbl{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--ns-muted)}
        .ns-tile-sub{font-size:11px;color:var(--ns-muted);margin-top:4px}
        .ns-tile-dot{width:12px;height:12px;border-radius:50%;position:absolute;top:14px;right:14px}
        .ns-tile.ok  {}
        .ns-tile.warn{}
        .ns-tile.bad {}
        .ns-tile.info{}
        .ns-tile.ok   .ns-tile-dot{background:var(--ns-green)}
        .ns-tile.warn .ns-tile-dot{background:var(--ns-orange)}
        .ns-tile.bad  .ns-tile-dot{background:var(--ns-red)}
        .ns-tile.info .ns-tile-dot{background:var(--ns-blue)}
        /* ── Security meter ── */
        .ns-meter-wrap{margin-bottom:20px}
        .ns-meter-header{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:10px}
        .ns-meter-score{font-size:42px;font-weight:800;line-height:1}
        .ns-meter-grade{font-size:22px;font-weight:700;margin-left:6px}
        .ns-meter-label{font-size:13px;color:var(--ns-muted);margin-bottom:4px;text-align:right}
        .ns-meter-bar{height:10px;background:var(--ns-border);border-radius:6px;overflow:hidden;margin-bottom:16px}
        .ns-meter-fill{height:100%;border-radius:6px;transition:width .6s ease}
        .ns-meter-steps{display:flex;flex-direction:column;gap:8px}
        .ns-step-row{display:flex;align-items:center;gap:10px;font-size:13px;padding:10px 14px;border-radius:8px;background:#f8fafc;border:1px solid var(--ns-border)}
        .ns-step-row.done{background:var(--ns-green-lt);border-color:#bbf7d0}
        .ns-step-row.todo{background:#fff;border-color:var(--ns-border)}
        .ns-step-row.bad{background:var(--ns-red-lt);border-color:#fecaca}
        .ns-step-icon{width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0}
        .done .ns-step-icon{background:var(--ns-green);color:#fff}
        .todo .ns-step-icon{background:var(--ns-border);color:var(--ns-muted)}
        .bad  .ns-step-icon{background:var(--ns-red);color:#fff}
        .ns-step-text{flex:1;color:var(--ns-text);font-weight:500}
        .ns-step-action{font-size:11px;font-weight:600;color:var(--ns-blue);text-decoration:none;white-space:nowrap}
        .ns-step-action:hover{text-decoration:underline}
        .ns-step-pts{font-size:11px;color:var(--ns-muted);white-space:nowrap}
        /* ── Buttons ── */
        .sh-btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:7px;font-size:13px;font-weight:600;cursor:pointer;border:none;text-decoration:none;transition:opacity .15s,transform .1s}
        .sh-btn:hover{opacity:.9;transform:translateY(-1px)} .sh-btn:disabled{opacity:.45;cursor:not-allowed}
        .sh-btn-red{background:var(--ns-red);color:#fff} .sh-btn-blue{background:var(--ns-blue);color:#fff}
        .sh-btn-green{background:var(--ns-green);color:#fff} .sh-btn-grey{background:#f1f5f9;color:#334155;border:1px solid var(--ns-border)}
        .sh-btn-orange{background:var(--ns-orange);color:#fff}
        /* ── Badges ── */
        .sh-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.3px}
        .sh-red{background:var(--ns-red-lt);color:var(--ns-red)} .sh-ok{background:var(--ns-green-lt);color:var(--ns-green)}
        .sh-warn{background:var(--ns-orange-lt);color:var(--ns-orange)} .sh-info{background:var(--ns-blue-lt);color:var(--ns-blue)}
        .sh-grey{background:#f1f5f9;color:var(--ns-grey)}
        /* ── Tables ── */
        table.sh-tbl{width:100%;border-collapse:collapse;font-size:13px}
        table.sh-tbl th{text-align:left;padding:9px 12px;background:#f8fafc;border-bottom:2px solid var(--ns-border);font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:var(--ns-muted)}
        table.sh-tbl td{padding:9px 12px;border-bottom:1px solid var(--ns-border);vertical-align:top;word-break:break-all}
        table.sh-tbl tr:last-child td{border-bottom:none}
        /* ── Forms ── */
        .sh-field{margin-bottom:18px}
        .sh-field label{display:block;font-weight:600;font-size:13px;margin-bottom:5px}
        .sh-field .desc{font-size:12px;color:var(--ns-muted);margin-top:4px}
        .sh-field input[type=text],.sh-field input[type=email],.sh-field textarea{width:100%;max-width:420px;padding:8px 10px;border:1px solid var(--ns-border);border-radius:6px;font-size:13px;box-sizing:border-box}
        .sh-field textarea{resize:vertical;max-width:100%;font-family:monospace}
        .sh-saved{background:var(--ns-green-lt);color:var(--ns-green);padding:10px 16px;border-radius:7px;margin-bottom:20px;font-size:13px;font-weight:600;border:1px solid #bbf7d0}
        .sh-err-box{background:var(--ns-red-lt);color:var(--ns-red);padding:10px 16px;border-radius:7px;margin-bottom:20px;font-size:13px;border:1px solid #fecaca}
        .sh-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px;align-items:center}
        /* ── Scanner ── */
        .sh-steps{list-style:none;margin:0;padding:0}
        .sh-step{display:flex;align-items:center;gap:14px;padding:10px 14px;border-radius:7px;margin-bottom:5px;font-size:13px;background:#f8fafc;border:1px solid var(--ns-border);transition:background .2s}
        .sh-step.step-waiting{color:var(--ns-muted)}
        .sh-step.step-running{background:var(--ns-blue-lt);border-color:#bfdbfe;color:var(--ns-blue-dk);font-weight:600}
        .sh-step.step-done{background:var(--ns-green-lt);border-color:#bbf7d0;color:#14532d}
        .sh-step.step-error{background:var(--ns-red-lt);border-color:#fecaca;color:var(--ns-red)}
        .sh-step-icon{width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0}
        .step-waiting .sh-step-icon{background:var(--ns-border);color:var(--ns-muted)}
        .step-running .sh-step-icon{background:var(--ns-blue);color:#fff}
        .step-done    .sh-step-icon{background:var(--ns-green);color:#fff}
        .step-error   .sh-step-icon{background:var(--ns-red);color:#fff}
        .sh-step-label{flex:1}.sh-step-meta{font-size:11px;opacity:.7;white-space:nowrap}
        .sh-step-threat{font-size:11px;font-weight:700;color:var(--ns-red);background:var(--ns-red-lt);padding:1px 8px;border-radius:10px;margin-right:6px}
        .sh-spin{display:inline-block;width:11px;height:11px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:sh-spin .6s linear infinite}
        @keyframes sh-spin{to{transform:rotate(360deg)}}
        .sh-overall-bar{height:6px;background:var(--ns-border);border-radius:4px;overflow:hidden;margin:14px 0 4px}
        .sh-overall-fill{height:100%;background:linear-gradient(90deg,var(--ns-blue),var(--ns-green));border-radius:4px;transition:width .4s ease;width:0}
        .sh-scan-summary{font-size:13px;color:var(--ns-muted);min-height:18px}
        .sh-threat-row-critical{background:#fff8f8}.sh-threat-row-warning{background:#fffdf0}
        .sh-threat-check{width:32px;text-align:center}
        .sh-sel-bar{background:var(--ns-blue-lt);border:1px solid #bfdbfe;border-radius:7px;padding:10px 16px;margin-bottom:12px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:13px}
        .sh-sel-count{font-weight:600;color:var(--ns-blue)}
        .sh-lic-box{border:2px solid;border-radius:8px;padding:20px;text-align:center;margin-bottom:24px}
        code{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:12px;font-family:monospace}
        pre{background:#1e293b;color:#94d8fb;padding:14px;border-radius:7px;font-size:12px;overflow-x:auto}
        /* ── Activity log ── */
        .ns-log{list-style:none;margin:0;padding:0}
        .ns-log li{display:flex;gap:12px;align-items:flex-start;padding:9px 0;border-bottom:1px solid var(--ns-border);font-size:13px}
        .ns-log li:last-child{border-bottom:none}
        .ns-log-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:5px}
        .ns-log-time{font-size:11px;color:var(--ns-muted);white-space:nowrap;min-width:100px}
        /* Lockdown ── */
        .ns-lock-indicator{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:4px 10px;border-radius:20px}
        .ns-lock-indicator.on{background:var(--ns-green-lt);color:var(--ns-green)}
        .ns-lock-indicator.off{background:var(--ns-red-lt);color:var(--ns-red)}
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
            if (fill){ fill.style.width='100%'; fill.style.background='var(--ns-green)'; }
            var sum = el('sh-scan-summary');
            var count = typeof tc !== 'undefined' ? tc : totalThreats;
            if (sum){
                sum.textContent = 'Scan complete · ' + totalFiles + ' file(s) · ' + (count > 0 ? count + ' threat(s) found' : 'No threats ✔');
                sum.style.color = count > 0 ? 'var(--ns-red)' : 'var(--ns-green)';
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
            if (fill){ fill.style.width='0'; fill.style.background='linear-gradient(90deg,var(--ns-blue),var(--ns-green))'; }
            var err = el('sh-scan-error');
            if (err) err.style.display='none';
            runStep(0);
        };

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
        $scan     = Shield_Scanner::get_last_scan();
        $settings = shield_get_settings();
        $lic      = Shield_License::get_status_label();
        $threats  = $scan ? intval( $scan['threat_count'] ) : null;
        $release  = Shield_Updater::get_latest_release();
        $latest   = $release ? ltrim( $release['tag_name'], 'v' ) : SHIELD_VERSION;
        $update   = version_compare( $latest, SHIELD_VERSION, '>' );

        // ── Security score ────────────────────────────────────────────
        $lock_status      = shield_get_lock_status();
        $uploads_blocked  = shield_uploads_php_blocked();
        $login_slug       = ! empty( $settings['login_slug'] );
        $file_mods_locked = $lock_status['file_mods'];
        $no_threats       = ( $threats === 0 );
        $scan_done        = ( $scan !== null );
        $email_alerts     = ! empty( $settings['email_alerts'] );
        $licensed         = shield_is_licensed();

        // Points: each check worth a different weight
        $checks = array(
            array(
                'key'    => 'scan',
                'done'   => $scan_done && $no_threats,
                'warn'   => $scan_done && ! $no_threats,
                'label'  => $scan_done
                             ? ( $no_threats ? 'No threats detected' : $threats . ' threat(s) detected — clean now' )
                             : 'Run your first scan',
                'action' => admin_url( 'admin.php?page=shield-scanner' ),
                'action_label' => $scan_done ? ( $no_threats ? 'Scan Again' : 'Clean Now' ) : 'Run Scan',
                'pts'    => 25,
            ),
            array(
                'key'    => 'lockdown',
                'done'   => $file_mods_locked,
                'warn'   => false,
                'label'  => $file_mods_locked ? 'Plugin installs locked (DISALLOW_FILE_MODS)' : 'Enable file modification lockdown',
                'action' => admin_url( 'admin.php?page=shield-lockdown' ),
                'action_label' => 'Lockdown',
                'pts'    => 20,
            ),
            array(
                'key'    => 'uploads',
                'done'   => (bool) $uploads_blocked,
                'warn'   => false,
                'label'  => $uploads_blocked ? 'PHP execution blocked in uploads' : 'Block PHP execution in uploads',
                'action' => admin_url( 'admin.php?page=shield-lockdown' ),
                'action_label' => 'Fix Now',
                'pts'    => 20,
            ),
            array(
                'key'    => 'login',
                'done'   => $login_slug,
                'warn'   => false,
                'label'  => $login_slug ? 'Custom login URL active' : 'Set a custom login URL',
                'action' => admin_url( 'admin.php?page=shield-login' ),
                'action_label' => 'Configure',
                'pts'    => 20,
            ),
            array(
                'key'    => 'alerts',
                'done'   => $email_alerts,
                'warn'   => false,
                'label'  => $email_alerts ? 'Email threat alerts enabled' : 'Enable email threat alerts',
                'action' => admin_url( 'admin.php?page=shield-settings' ),
                'action_label' => 'Settings',
                'pts'    => 15,
            ),
        );

        $score = 0;
        foreach ( $checks as $c ) {
            if ( $c['done'] ) $score += $c['pts'];
            elseif ( isset( $c['warn'] ) && $c['warn'] ) $score += intval( $c['pts'] / 2 );
        }
        $score = min( 100, $score );

        if ( $score >= 80 )      { $grade = 'A'; $grade_color = '#16a34a'; $meter_color = '#16a34a'; $grade_label = 'Strong'; }
        elseif ( $score >= 60 )  { $grade = 'B'; $grade_color = '#65a30d'; $meter_color = '#84cc16'; $grade_label = 'Good'; }
        elseif ( $score >= 40 )  { $grade = 'C'; $grade_color = '#d97706'; $meter_color = '#f59e0b'; $grade_label = 'Fair'; }
        else                     { $grade = 'D'; $grade_color = '#dc2626'; $meter_color = '#ef4444'; $grade_label = 'At Risk'; }

        // ── Scan age ─────────────────────────────────────────────────
        $scan_age_text = 'Never scanned';
        $scan_age_class = 'bad';
        if ( $scan ) {
            $scanned_at = strtotime( $scan['completed_at'] );
            $age_secs   = time() - $scanned_at;
            $age_days   = floor( $age_secs / 86400 );
            $age_hours  = floor( $age_secs / 3600 );
            if ( $age_days >= 14 )     { $scan_age_text = $age_days . ' days ago'; $scan_age_class = 'bad'; }
            elseif ( $age_days >= 7 )  { $scan_age_text = $age_days . ' days ago'; $scan_age_class = 'warn'; }
            elseif ( $age_days >= 1 )  { $scan_age_text = $age_days . ' day' . ( $age_days > 1 ? 's' : '' ) . ' ago'; $scan_age_class = 'ok'; }
            elseif ( $age_hours >= 1 ) { $scan_age_text = $age_hours . 'h ago'; $scan_age_class = 'ok'; }
            else                       { $scan_age_text = 'Just now'; $scan_age_class = 'ok'; }
        }
        ?>
        <div id="shield-wrap">
        <h1>🛡 NovaShield <span class="ns-ver">v<?php echo esc_html( SHIELD_VERSION ); ?></span></h1>

        <!-- ── Status Tiles ── -->
        <div class="ns-tiles">

            <!-- Scanner tile -->
            <a href="<?php echo admin_url( 'admin.php?page=shield-scanner' ); ?>" class="ns-tile <?php echo $threats === null ? 'info' : ( $threats > 0 ? 'bad' : 'ok' ); ?>">
                <div class="ns-tile-dot"></div>
                <div class="ns-tile-top">
                    <div class="ns-tile-icon">🔍</div>
                    <div class="ns-tile-val"><?php echo $threats === null ? '—' : $threats; ?></div>
                </div>
                <div class="ns-tile-lbl">Threats</div>
                <div class="ns-tile-sub"><?php echo esc_html( $scan_age_text ); ?></div>
            </a>

            <!-- Lockdown tile -->
            <a href="<?php echo admin_url( 'admin.php?page=shield-lockdown' ); ?>" class="ns-tile <?php echo $file_mods_locked ? 'ok' : 'bad'; ?>">
                <div class="ns-tile-dot"></div>
                <div class="ns-tile-top">
                    <div class="ns-tile-icon"><?php echo $file_mods_locked ? '🔒' : '🔓'; ?></div>
                    <div class="ns-tile-val" style="font-size:15px;"><?php echo $file_mods_locked ? 'Locked' : 'Unlocked'; ?></div>
                </div>
                <div class="ns-tile-lbl">Lockdown</div>
                <div class="ns-tile-sub"><?php echo $uploads_blocked ? 'Uploads blocked ✔' : 'Uploads open ⚠'; ?></div>
            </a>

            <!-- Login tile -->
            <a href="<?php echo admin_url( 'admin.php?page=shield-login' ); ?>" class="ns-tile <?php echo $login_slug ? 'ok' : 'bad'; ?>">
                <div class="ns-tile-dot"></div>
                <div class="ns-tile-top">
                    <div class="ns-tile-icon">🔑</div>
                    <div class="ns-tile-val" style="font-size:15px;"><?php echo $login_slug ? 'Custom URL' : 'Default URL'; ?></div>
                </div>
                <div class="ns-tile-lbl">Login Security</div>
                <div class="ns-tile-sub"><?php echo $login_slug ? 'wp-login.php hidden ✔' : 'wp-login.php exposed'; ?></div>
            </a>

            <!-- Version tile -->
            <a href="<?php echo admin_url( 'update-core.php' ); ?>" class="ns-tile <?php echo $update ? 'warn' : 'ok'; ?>">
                <div class="ns-tile-dot"></div>
                <div class="ns-tile-top">
                    <div class="ns-tile-icon">⚡</div>
                    <div class="ns-tile-val" style="font-size:15px;">v<?php echo esc_html( SHIELD_VERSION ); ?></div>
                </div>
                <div class="ns-tile-lbl">Plugin Version</div>
                <div class="ns-tile-sub"><?php echo $update ? 'v' . esc_html( $latest ) . ' available ↑' : 'Up to date ✔'; ?></div>
            </a>

        </div>

        <!-- ── Two-column layout: Score + Activity ── -->
        <div class="sh-card-row">

            <!-- Security Score -->
            <div class="sh-card">
                <h2>📊 Security Score</h2>
                <div class="ns-meter-wrap">
                    <div class="ns-meter-header">
                        <div>
                            <span class="ns-meter-score" style="color:<?php echo $grade_color; ?>"><?php echo $score; ?></span>
                            <span class="ns-meter-grade" style="color:<?php echo $grade_color; ?>">/ 100</span>
                        </div>
                        <div>
                            <div class="ns-meter-label" style="color:<?php echo $grade_color; ?>;font-weight:700;font-size:16px;"><?php echo $grade_label; ?></div>
                            <div class="ns-meter-label">Grade <?php echo $grade; ?></div>
                        </div>
                    </div>
                    <div class="ns-meter-bar">
                        <div class="ns-meter-fill" style="width:<?php echo $score; ?>%;background:<?php echo $meter_color; ?>;"></div>
                    </div>
                    <div class="ns-meter-steps">
                        <?php foreach ( $checks as $c ) :
                            $row_class = $c['done'] ? 'done' : ( ( isset( $c['warn'] ) && $c['warn'] ) ? 'bad' : 'todo' );
                            $icon      = $c['done'] ? '✔' : ( ( isset( $c['warn'] ) && $c['warn'] ) ? '!' : '○' );
                        ?>
                        <div class="ns-step-row <?php echo $row_class; ?>">
                            <div class="ns-step-icon"><?php echo $icon; ?></div>
                            <div class="ns-step-text"><?php echo esc_html( $c['label'] ); ?></div>
                            <?php if ( ! $c['done'] ) : ?>
                            <a href="<?php echo esc_url( $c['action'] ); ?>" class="ns-step-action"><?php echo esc_html( $c['action_label'] ); ?> →</a>
                            <?php endif; ?>
                            <div class="ns-step-pts"><?php echo $c['pts']; ?>pts</div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <!-- Recent Activity + Quick Actions -->
            <div>
                <div class="sh-card" style="margin-bottom:14px;">
                    <h2>⚡ Quick Actions</h2>
                    <div class="sh-actions" style="margin-top:0;">
                        <a href="<?php echo admin_url( 'admin.php?page=shield-scanner' ); ?>"  class="sh-btn sh-btn-blue">🔍 Run Scan</a>
                        <a href="<?php echo admin_url( 'admin.php?page=shield-lockdown' ); ?>" class="sh-btn sh-btn-<?php echo $file_mods_locked ? 'grey' : 'orange'; ?>">🔒 Lockdown</a>
                        <a href="<?php echo admin_url( 'admin.php?page=shield-login' ); ?>"    class="sh-btn sh-btn-grey">🔑 Login Security</a>
                        <a href="<?php echo admin_url( 'admin.php?page=shield-settings' ); ?>" class="sh-btn sh-btn-grey">⚙ Settings</a>
                        <?php if ( $update ) : ?>
                        <a href="<?php echo admin_url( 'update-core.php' ); ?>" class="sh-btn sh-btn-green">⬆ Update</a>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="sh-card">
                    <h2>📋 Recent Activity</h2>
                    <?php $logs = get_option( 'shield_scan_log', array() ); ?>
                    <?php if ( empty( $logs ) ) : ?>
                        <p style="color:var(--ns-muted);font-size:13px;margin:0;">No activity yet. Run a scan to get started.</p>
                    <?php else : ?>
                    <ul class="ns-log">
                        <?php foreach ( array_reverse( array_slice( $logs, -8 ) ) as $entry ) :
                            $lvl = $entry['level'] ?? 'info';
                            $dot_color = ( $lvl === 'warn' ) ? 'var(--ns-orange)' : ( ( $lvl === 'error' ) ? 'var(--ns-red)' : 'var(--ns-green)' );
                            $ts  = strtotime( $entry['time'] ?? '' );
                            $ago = $ts ? human_time_diff( $ts, time() ) . ' ago' : '';
                        ?>
                        <li>
                            <div class="ns-log-dot" style="background:<?php echo $dot_color; ?>"></div>
                            <div style="flex:1;font-size:13px;"><?php echo esc_html( $entry['message'] ?? '' ); ?></div>
                            <div class="ns-log-time"><?php echo esc_html( $ago ); ?></div>
                        </li>
                        <?php endforeach; ?>
                    </ul>
                    <?php endif; ?>
                </div>
            </div>

        </div>
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
                            <?php
                        $type_label = $threat['type'] ?? '';
                        if ( $type_label === 'webshell' ) : ?>
                            <span class="sh-badge sh-red">⚠ WEBSHELL</span>
                        <?php elseif ( $sev === 'critical' ) : ?>
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

    // ═══════════════════════════════════════════════════════════════════
    // LOCKDOWN PAGE
    // ═══════════════════════════════════════════════════════════════════
    public static function page_lockdown() {
        if ( ! current_user_can( 'manage_options' ) ) return;

        $lock   = shield_get_lock_status();
        $msg    = isset( $_GET['msg'] ) ? sanitize_key( $_GET['msg'] ) : '';
        $fm_on  = $lock['file_mods'];   // DISALLOW_FILE_MODS active?
        $fe_on  = $lock['file_edit'];   // DISALLOW_FILE_EDIT active?
        $writable = $lock['wpconfig_writable'];
        ?>
        <div id="shield-wrap">
        <h1>🔒 Lockdown — File Modification Controls</h1>
        <p style="color:#666;margin-bottom:24px;">
            Prevent WordPress from installing, updating, or deleting plugins and themes.
            Toggle off temporarily when you need to add a legitimate plugin, then re-enable.
        </p>

        <?php if ( $msg === 'uploads_blocked' ) : ?>
            <div class="sh-saved">🚫 PHP execution blocked in uploads directory (.htaccess written).</div>
        <?php elseif ( $msg === 'uploads_unblocked' ) : ?>
            <div class="sh-saved" style="background:#fff3cd;color:#856404;">🔓 Uploads PHP block removed. Re-enable after maintenance.</div>
        <?php elseif ( $msg === 'nginx_marked' ) : ?>
            <div class="sh-saved">✔ Nginx block marked as configured.</div>
        <?php elseif ( $msg === 'nginx_unmarked' ) : ?>
            <div class="sh-saved" style="background:#d1ecf1;color:#0c5460;">Nginx block mark removed.</div>
        <?php elseif ( $msg === 'lock_enabled' ) : ?>
            <div class="sh-saved">🔒 File modifications locked. No one can install, update, or delete plugins or themes.</div>
        <?php elseif ( $msg === 'lock_disabled' ) : ?>
            <div class="sh-saved" style="background:#fff3cd;color:#856404;">🔓 Lock removed. WordPress can now install and modify plugins and themes. Re-enable when done.</div>
        <?php elseif ( $msg === 'edit_lock_enabled' ) : ?>
            <div class="sh-saved">🔒 Theme/plugin file editor disabled.</div>
        <?php elseif ( $msg === 'edit_lock_disabled' ) : ?>
            <div class="sh-saved" style="background:#fff3cd;color:#856404;">🔓 Theme/plugin file editor re-enabled.</div>
        <?php elseif ( $msg === 'lock_error' ) : ?>
            <div class="sh-err-box">⚠ Could not write to wp-config.php. Check file permissions or add the define manually (see below).</div>
        <?php endif; ?>

        <?php if ( ! $writable ) : ?>
        <div class="sh-err-box" style="margin-bottom:20px;">
            ⚠ <strong>wp-config.php is not writable.</strong> Shield cannot toggle these settings automatically.
            You can add/remove the defines manually — see the manual instructions at the bottom of this page.
        </div>
        <?php endif; ?>

        <!-- Main Toggle: DISALLOW_FILE_MODS -->
        <div class="sh-card" style="border-left: 4px solid <?php echo $fm_on ? '#27ae60' : '#e74c3c'; ?>;">
            <h2>
                <?php echo $fm_on ? '🔒' : '🔓'; ?> Plugin &amp; Theme Installation Lock
                <?php if ( $fm_on ) : ?>
                    <span class="sh-badge sh-ok">ACTIVE — Locked</span>
                <?php else : ?>
                    <span class="sh-badge sh-red">INACTIVE — Unlocked</span>
                <?php endif; ?>
            </h2>

            <p style="font-size:13px;color:#555;margin-bottom:16px;">
                Sets <code>DISALLOW_FILE_MODS</code> in <code>wp-config.php</code>.
                When enabled, WordPress completely blocks:
            </p>
            <table class="sh-tbl" style="margin-bottom:16px;">
                <tbody>
                    <tr><td>🚫</td><td>Installing new plugins</td></tr>
                    <tr><td>🚫</td><td>Installing new themes</td></tr>
                    <tr><td>🚫</td><td>Updating existing plugins or themes</td></tr>
                    <tr><td>🚫</td><td>Deleting plugins or themes via wp-admin</td></tr>
                    <tr><td>🚫</td><td>Editing plugin or theme files via the built-in editor</td></tr>
                    <tr><td>🚫</td><td>WordPress core auto-updates</td></tr>
                </tbody>
            </table>

            <?php if ( $fm_on ) : ?>
            <div style="background:#d4edda;border-radius:6px;padding:12px 16px;font-size:13px;margin-bottom:16px;">
                ✔ <strong>Lock is active.</strong> Malware cannot self-install or reinstall via WordPress.
                To add a legitimate plugin, click Unlock below, install the plugin, then re-lock immediately.
            </div>
            <form method="post">
                <?php shield_nonce_field(); ?>
                <input type="hidden" name="shield_lock_action" value="disable_file_mods_lock">
                <button type="submit" class="sh-btn sh-btn-orange"
                    onclick="return confirm('Unlock file modifications? Anyone with admin access will be able to install plugins. Re-lock as soon as you are done.')">
                    🔓 Temporarily Unlock
                </button>
            </form>
            <?php else : ?>
            <div style="background:#fdecea;border-radius:6px;padding:12px 16px;font-size:13px;margin-bottom:16px;">
                ⚠ <strong>Lock is off.</strong> Plugins and themes can be installed or modified freely.
                Enable this lock to prevent malware reinstallation.
            </div>
            <form method="post">
                <?php shield_nonce_field(); ?>
                <input type="hidden" name="shield_lock_action" value="enable_file_mods_lock">
                <button type="submit" class="sh-btn sh-btn-green"
                    onclick="return confirm('Lock all plugin and theme modifications? WordPress updates will also be blocked while this is active.')">
                    🔒 Enable Lock
                </button>
            </form>
            <?php endif; ?>
        </div>

        <!-- Secondary Toggle: DISALLOW_FILE_EDIT only -->
        <div class="sh-card" style="border-left: 4px solid <?php echo ( $fe_on || $fm_on ) ? '#27ae60' : '#ddd'; ?>;">
            <h2>
                <?php echo ( $fe_on || $fm_on ) ? '🔒' : '🔓'; ?> Theme &amp; Plugin File Editor
                <?php if ( $fe_on || $fm_on ) : ?>
                    <span class="sh-badge sh-ok">Disabled</span>
                <?php else : ?>
                    <span class="sh-badge sh-grey">Enabled (default)</span>
                <?php endif; ?>
            </h2>
            <p style="font-size:13px;color:#555;margin-bottom:14px;">
                Sets <code>DISALLOW_FILE_EDIT</code> in <code>wp-config.php</code>.
                A lighter option — disables only the <strong>Appearance → Theme File Editor</strong>
                and <strong>Plugins → Plugin File Editor</strong> menus, without blocking plugin/theme installation.
                If the full lock above is active, the file editor is already blocked automatically.
            </p>
            <?php if ( $fm_on ) : ?>
                <p style="font-size:13px;color:#888;font-style:italic;">This is already covered by the full lock above.</p>
            <?php elseif ( $fe_on ) : ?>
                <form method="post">
                    <?php shield_nonce_field(); ?>
                    <input type="hidden" name="shield_lock_action" value="disable_file_edit_lock">
                    <button type="submit" class="sh-btn sh-btn-orange"
                        onclick="return confirm('Re-enable the theme and plugin file editor?')">
                        🔓 Re-enable File Editor
                    </button>
                </form>
            <?php else : ?>
                <form method="post">
                    <?php shield_nonce_field(); ?>
                    <input type="hidden" name="shield_lock_action" value="enable_file_edit_lock">
                    <button type="submit" class="sh-btn sh-btn-blue">
                        🔒 Disable File Editor Only
                    </button>
                </form>
            <?php endif; ?>
        </div>

        <!-- Uploads PHP Execution Block -->
        <?php
        $uploads_block_status = shield_uploads_php_blocked();
        $is_kinsta = ( defined( 'KINSTA_CACHE_ZONE' ) || strpos( $_SERVER['SERVER_SOFTWARE'] ?? '', 'nginx' ) !== false );
        ?>
        <div class="sh-card" style="border-left: 4px solid <?php echo $uploads_block_status ? '#27ae60' : '#e74c3c'; ?>;">
            <h2>
                <?php echo $uploads_block_status ? '🚫' : '⚠️'; ?> Block PHP Execution in Uploads
                <?php if ( $uploads_block_status === 'htaccess' ) : ?>
                    <span class="sh-badge sh-ok">BLOCKED via .htaccess</span>
                <?php elseif ( $uploads_block_status === 'nginx' ) : ?>
                    <span class="sh-badge sh-ok">BLOCKED via Nginx (manual)</span>
                <?php else : ?>
                    <span class="sh-badge sh-red">NOT BLOCKED — Critical Risk</span>
                <?php endif; ?>
            </h2>

            <p style="font-size:13px;color:#555;margin-bottom:12px;">
                PHP files should <strong>never</strong> exist in <code>wp-content/uploads/</code>.
                Attackers hide webshells there (like <code>wp-cache-stats.php</code>) because most
                security plugins only scan — they don't block execution. This toggle prevents
                any PHP file in uploads from ever running, even if one gets uploaded.
            </p>

            <?php if ( ! $uploads_block_status ) : ?>
            <div style="background:#fdecea;border-radius:6px;padding:12px 16px;font-size:13px;margin-bottom:16px;">
                ⚠ <strong>Currently unblocked.</strong> Any PHP file uploaded to <code>wp-content/uploads/</code>
                can be executed by the attacker. This is how <code>wp-cache-stats.php</code> worked —
                it restored deleted malware from the database on demand.
            </div>
            <?php endif; ?>

            <?php if ( $is_kinsta ) : ?>
            <!-- Kinsta uses Nginx — show manual rule + mark-as-done button -->
            <div style="background:#f0f6ff;border:1px solid #b8d4f5;border-radius:6px;padding:14px 16px;margin-bottom:14px;">
                <p style="font-size:13px;font-weight:600;margin:0 0 8px;">Kinsta / Nginx: Add this rule manually</p>
                <pre style="background:#1e1e1e;color:#4ec9b0;padding:12px;border-radius:5px;font-size:12px;overflow-x:auto;margin:0;"><?php echo esc_html( shield_get_nginx_uploads_rule() ); ?></pre>
                <p style="font-size:12px;color:#666;margin:8px 0 0;">
                    In MyKinsta → Sites → your site → <strong>Nginx configuration</strong> → paste this rule → Save.
                    Then click "Mark as configured" below.
                </p>
            </div>
            <div class="sh-actions">
                <?php if ( $uploads_block_status !== 'nginx' ) : ?>
                <form method="post">
                    <?php shield_nonce_field(); ?>
                    <input type="hidden" name="shield_lock_action" value="mark_nginx_blocked">
                    <button type="submit" class="sh-btn sh-btn-green">✔ Mark Nginx Rule as Configured</button>
                </form>
                <?php else : ?>
                <form method="post">
                    <?php shield_nonce_field(); ?>
                    <input type="hidden" name="shield_lock_action" value="unmark_nginx_blocked">
                    <button type="submit" class="sh-btn sh-btn-grey">Remove Mark</button>
                </form>
                <?php endif; ?>
            </div>
            <?php else : ?>
            <!-- Apache/LiteSpeed — automatic .htaccess write -->
            <div class="sh-actions">
                <?php if ( ! $uploads_block_status ) : ?>
                <form method="post">
                    <?php shield_nonce_field(); ?>
                    <input type="hidden" name="shield_lock_action" value="block_uploads_php">
                    <button type="submit" class="sh-btn sh-btn-green"
                        onclick="return confirm('Block PHP execution in uploads? This writes a .htaccess rule. No PHP files in uploads will be executable.')">
                        🚫 Block PHP in Uploads
                    </button>
                </form>
                <?php else : ?>
                <form method="post">
                    <?php shield_nonce_field(); ?>
                    <input type="hidden" name="shield_lock_action" value="unblock_uploads_php">
                    <button type="submit" class="sh-btn sh-btn-orange"
                        onclick="return confirm('Remove the uploads PHP block? Only do this for maintenance, then re-enable immediately.')">
                        🔓 Temporarily Unblock
                    </button>
                </form>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>

        <!-- Current wp-config.php status -->
        <div class="sh-card">
            <h2>📋 Current wp-config.php Status</h2>
            <table class="sh-tbl"><tbody>
                <tr>
                    <td><code>DISALLOW_FILE_MODS</code></td>
                    <td><?php echo $fm_on
                        ? '<span class="sh-badge sh-ok">✔ Defined by Shield</span>'
                        : '<span class="sh-badge sh-grey">Not set</span>'; ?></td>
                    <td style="font-size:12px;color:#888;">Blocks all plugin/theme installs, updates, deletions</td>
                </tr>
                <tr>
                    <td><code>DISALLOW_FILE_EDIT</code></td>
                    <td><?php echo ( $fe_on || $fm_on )
                        ? '<span class="sh-badge sh-ok">✔ ' . ( $fm_on ? 'Implied by FILE_MODS' : 'Defined by Shield' ) . '</span>'
                        : '<span class="sh-badge sh-grey">Not set</span>'; ?></td>
                    <td style="font-size:12px;color:#888;">Blocks theme/plugin file editor only</td>
                </tr>
                <tr>
                    <td>wp-config.php writable</td>
                    <td><?php echo $writable
                        ? '<span class="sh-badge sh-ok">✔ Yes</span>'
                        : '<span class="sh-badge sh-warn">⚠ No — manual edit required</span>'; ?></td>
                    <td style="font-size:12px;color:#888;"></td>
                </tr>
            </tbody></table>
        </div>

        <!-- Manual instructions (shown always, important for non-writable configs) -->
        <div class="sh-card" style="border-left:4px solid #2271b1;">
            <h2>📖 Manual Instructions (if auto-toggle fails)</h2>
            <p style="font-size:13px;color:#555;margin-bottom:12px;">If wp-config.php is not writable, add or remove these lines manually via SFTP:</p>
            <p style="font-size:13px;font-weight:600;margin-bottom:6px;">To lock (add after <code>&lt;?php</code>):</p>
            <pre style="background:#1e1e1e;color:#4ec9b0;padding:14px;border-radius:6px;font-size:12px;overflow-x:auto;">define( 'DISALLOW_FILE_MODS', true ); // Blocks all plugin/theme installs</pre>
            <p style="font-size:13px;font-weight:600;margin-top:14px;margin-bottom:6px;">To unlock (remove that line):</p>
            <p style="font-size:13px;color:#666;">Delete the <code>define( 'DISALLOW_FILE_MODS', true );</code> line from wp-config.php and save.</p>
            <p style="font-size:13px;color:#888;margin-top:12px;">
                ⚠ <strong>Important:</strong> While the lock is active, WordPress core security updates are also blocked.
                Check for WordPress core updates manually and apply them via SFTP or WP-CLI if needed.
                Alternatively, unlock → update core → re-lock.
            </p>
        </div>

        <!-- Recommended workflow -->
        <div class="sh-card" style="border-left:4px solid #27ae60;">
            <h2>✅ Recommended Workflow</h2>
            <table class="sh-tbl"><tbody>
                <tr><td>1️⃣</td><td><strong>After malware cleanup:</strong> Enable the full lock immediately</td></tr>
                <tr><td>2️⃣</td><td><strong>When you need to add a plugin:</strong> Click Temporarily Unlock → install plugin → re-lock</td></tr>
                <tr><td>2️⃣</td><td><strong>Block PHP in uploads:</strong> Enable the uploads block above — prevents webshell execution even if files slip through</td></tr>
                <tr><td>3️⃣</td><td><strong>For WordPress core updates:</strong> Unlock → update → re-lock</td></tr>
                <tr><td>4️⃣</td><td><strong>For theme edits:</strong> Use a local editor + SFTP instead of the built-in editor</td></tr>
                <tr><td>5️⃣</td><td>Keep lock ON at all times on client sites you manage remotely</td></tr>
            </tbody></table>
        </div>

        </div>
        <?php
    }
}
