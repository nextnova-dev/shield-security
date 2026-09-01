<?php
/**
 * Plugin Name: Shield Security
 * Plugin URI:  https://github.com/nextnova-dev/shield-security
 * Description: Professional WordPress security — malware scanner, login hardening, file lockdown, auto-updates.
 * Version:     1.3.3
 * Author:      Next Nova Technologies
 * Author URI:  https://nextnovatechnologies.com
 * License:     GPL-2.0+
 * Text Domain: shield-security
 * Requires PHP: 7.0
 * Requires at least: 5.0
 */
if ( ! defined( 'ABSPATH' ) ) exit;
if ( version_compare( PHP_VERSION, '7.0.0', '<' ) ) {
    add_action( 'admin_notices', function () {
        echo '<div class="notice notice-error"><p><strong>Shield Security</strong> requires PHP 7.0+.</p></div>';
    } );
    return;
}
define( 'SHIELD_VERSION',     '1.3.3' );
define( 'SHIELD_SLUG',        'shield-security' );
define( 'SHIELD_FILE',        __FILE__ );
define( 'SHIELD_DIR',         plugin_dir_path( __FILE__ ) );
define( 'SHIELD_URL',         plugin_dir_url( __FILE__ ) );
define( 'SHIELD_OPT',         'shield_settings' );
define( 'SHIELD_LIC_OPT',     'shield_license' );
define( 'SHIELD_GITHUB_REPO', 'nextnova-dev/shield-security' );
require_once SHIELD_DIR . 'includes/helpers.php';
require_once SHIELD_DIR . 'includes/settings.php';
require_once SHIELD_DIR . 'includes/license.php';
require_once SHIELD_DIR . 'includes/updater.php';
require_once SHIELD_DIR . 'includes/scanner.php';
require_once SHIELD_DIR . 'includes/login-hardening.php';
require_once SHIELD_DIR . 'includes/cleanup.php';
require_once SHIELD_DIR . 'includes/admin-ui.php';
Shield_Settings::init();
Shield_License::init();
Shield_Updater::init();
Shield_Login_Hardening::init();
Shield_File_Lock::init();
Shield_Admin_UI::init();
register_activation_hook( __FILE__, array( 'Shield_Settings', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Shield_Login_Hardening', 'deactivate' ) );
