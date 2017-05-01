<?php

/**
 * Disallow direct access to this file for security reasons
 */
if (!defined("IN_MYBB")) {
    die("Direct initialization of this file is not allowed.");
}

// Require our Project HoneyPot class
require('honeypot/honeypot.class.php');

/**
 * Define our hooks
 */
$plugins->add_hook('member_do_register_start', 'honeypot_register_start');
$plugins->add_hook('admin_tools_menu_logs', 'honeypot_admin_tools_menu_logs');
$plugins->add_hook('admin_tools_action_handler', 'honeypot_admin_tools_action_handler');
$plugins->add_hook('admin_tools_permissions', 'honeypot_admin_tools_permissions');
$plugins->add_hook('admin_config_settings_change_commit', 'honeypot_admin_config_settings_change_commit');

/**
 * Returns an array of information about this plugin
 */
function honeypot_info()
{
    global $lang;
    $lang->load("honeypot", true);

    return array(
        "name" => "Project HoneyPot for MyBB",
        "description" => $lang->honeypot_desc,
        "website" => "http://www.jamiesage.co.uk",
        "author" => "Jamie Sage",
        "authorsite" => "http://www.jamiesage.co.uk",
        "version" => "0.1",
        "guid" => "",
        "codename" => str_replace('.php', '', basename(__FILE__)),
        "compatibility" => "18*"
    );
}

/**
 * Install Project HoneyPot
 */
function honeypot_install()
{
    global $db, $lang;
    $lang->load("honeypot", true);

    // Settings
    $setting_group = array(
        'name' => 'honeypot',
        'title' => $lang->honeypot,
        'description' => $lang->honeypot_desc,
        'disporder' => 5,
        'isdefault' => 0
    );
    $gid = $db->insert_query("settinggroups", $setting_group);

    $setting = array(
        "name" => "honeypot_accesskey",
        "title" => $lang->honeypot_accesskey,
        "description" => $lang->honeypot_accesskey_desc,
        "optionscode" => "text",
        "value" => "",
        "disporder" => 1,
        "gid" => $gid
    );
    $db->insert_query("settings", $setting);


    $setting = array(
        "name" => "honeypot_threatlevel",
        "title" => $lang->honeypot_threatlevel,
        "description" => $lang->honeypot_threatlevel_desc,
        "optionscode" => "numeric",
        "value" => "25",
        "disporder" => 1,
        "gid" => $gid
    );
    $db->insert_query("settings", $setting);

    // Create out logs table
    if (!$db->table_exists('fc_fields')) {
        $db->write_query("
            CREATE TABLE `" . TABLE_PREFIX . "project_honeypot` (
            `id` INT NOT NULL AUTO_INCREMENT,
            `username` VARCHAR(255) NOT NULL,
            `email` VARCHAR(255) NOT NULL,
            `last_activity` INT NOT NULL,
            `threat_score` INT NOT NULL,
            `visitor_type` VARCHAR(255) NOT NULL,
            `ip_address` VARCHAR(255) NOT NULL,
            `created_at`INT NOT NULL,
            PRIMARY KEY (`id`));
        ");
    }
    // Rebuild settings
    rebuild_settings();
}

/**
 * Check if Project HoneyPot is installed
 * @return bool
 */
function honeypot_is_installed()
{
    global $mybb;
    return isset($mybb->settings['honeypot_accesskey']);
}

/**
 * Called when the plugin is uninstalled
 */
function honeypot_uninstall()
{
    global $db;

    // Delete the settings
    $db->delete_query('settings', "name IN ('honeypot_accesskey', 'honeypot_threatlevel')");
    $db->delete_query('settinggroups', "name = 'honeypot'");

    // Drop the log table
    $db->drop_table('project_honeypot');

    // Rebuild settings
    rebuild_settings();
}

/**
 * Hook into the register process
 * @return bool
 */
function honeypot_register_start()
{
    global $mybb, $db;

    if (isHoneyPotActive()) {
        $ip_address = $_SERVER['REMOTE_ADDR'];
        try {
            $honeypot = new ProjectHoneyPot\HoneyPot($ip_address, $mybb->settings['honeypot_accesskey']);

            if (isThreat($honeypot->getThreatScore())) {
                // Log this event
                $data = [
                    'username' => $db->escape_string($mybb->get_input('username')),
                    'email' => $db->escape_string($mybb->get_input('email')),
                    'ip_address' => $db->escape_string($ip_address),
                    'created_at' => (int)TIME_NOW
                ];
                $db->insert_query('project_honeypot', array_merge($data, $honeypot->all()));

                header('HTTP/1.0 403 Forbidden');
                die("You have been flagged as '" . $honeypot->getVisitorType() . "'. Therefore, you cannot register."); // TODO: Customisable text
                return false;
            }
        } catch (\Exception $e) {
            // TODO: We should log this event and alert the administrators of the error
        }
    }
    return true;
}

/**
 * Add Project HoneyPot menu item to the ACP
 * @param $sub_menu
 */
function honeypot_admin_tools_menu_logs(&$sub_menu)
{
    global $lang;
    $lang->load("honeypot", true);

    $sub_menu[] = [
        'id' => 'honeypot',
        'title' => $lang->honeypot,
        'link' => 'index.php?module=tools-honeypot'
    ];
}

/**
 * Add Project HoneyPot to the tool handler
 * @param $actions
 */
function honeypot_admin_tools_action_handler(&$actions)
{
    $actions['honeypot'] = [
        'active' => 'honeypot',
        'file' => 'honeypot.php'
    ];
}

/**
 * Hook into the settings change commit
 * @return bool|void
 */
function honeypot_admin_config_settings_change_commit()
{
    global $mybb, $db;
    $query = $db->simple_select('settinggroups', '*', 'gid = ' . $db->escape_string($mybb->get_input('gid')), ["limit" => 1]);
    $settings = $db->fetch_array($query);

    // Make sure the user is editing our plugin
    if ($settings["name"] === 'honeypot') {
        // Test the users access key to verify if it is valid
        try {
            new ProjectHoneyPot\HoneyPot($_SERVER['REMOTE_ADDR'], $mybb->settings['honeypot_accesskey']);
        } catch (\Exception $e) {
            flash_message($e->getMessage(), 'error');
            admin_redirect("index.php?module=config-settings&action=change&gid=" . $mybb->get_input('gid'));
            return die();
        }
    }
    return true;
}

/**
 * Check if all the necessary settings are available for Project HoneyPot to be acitve
 */
function isHoneyPotActive()
{
    global $mybb;

    // Validate the access key
    if (!ProjectHoneyPot\HoneyPot::isValidAccessKey($mybb->settings['honeypot_accesskey'])) {
        return false;
    }

    // Validate the threat level
    if ($mybb->settings['honeypot_threatlevel'] < 0) {
        return false;
    }
    return true;
}

/**
 * Check if a threat score hits our threshold
 * @param $threat_score
 * @return bool
 */
function isThreat($threat_score)
{
    global $mybb;
    return $threat_score > $mybb->settings['honeypot_threatlevel'];
}
