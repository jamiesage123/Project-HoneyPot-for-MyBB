<?php
// Disallow direct access to this file for security reasons
if (!defined("IN_MYBB")) {
    die("Direct initialization of this file is not allowed.<br /><br />Please make sure IN_MYBB is defined.");
}

$page->add_breadcrumb_item($lang->honeypot, "index.php?module=tools-honeypot");

$sub_tabs['honeypot'] = array(
    'title' => $lang->honeypot,
    'link' => "index.php?module=tools-honeypot",
    'description' => $lang->honeypot_logs_desc
);

if (!$mybb->input['action']) {
    $page->output_header($lang->spam_logs);

    $page->output_nav_tabs($sub_tabs, 'honeypot');

    $perpage = $mybb->get_input('perpage', MyBB::INPUT_INT);
    if (!$perpage) {
        $perpage = 20;
    }

    $query = $db->simple_select("project_honeypot", "COUNT(id) AS count");
    $rescount = $db->fetch_field($query, "count");

    // Figure out if we need to display multiple pages.
    if ($mybb->input['page'] != "last") {
        $pagecnt = $mybb->get_input('page', MyBB::INPUT_INT);
    }

    $logcount = (int)$rescount;
    $pages = $logcount / $perpage;
    $pages = ceil($pages);

    if ($mybb->input['page'] == "last") {
        $pagecnt = $pages;
    }

    if ($pagecnt > $pages) {
        $pagecnt = 1;
    }

    if ($pagecnt) {
        $start = ($pagecnt - 1) * $perpage;
    } else {
        $start = 0;
        $pagecnt = 1;
    }

    $table = new Table;
    $table->construct_header($lang->honeypot_username, ['width' => '14.14%']);
    $table->construct_header($lang->honeypot_email, ['width' => '14.14%']);
    $table->construct_header($lang->honeypot_last_activity, ['width' => '14.14%']);
    $table->construct_header($lang->honeypot_threat_score, ['width' => '14.14%']);
    $table->construct_header($lang->honeypot_visitor_type, ['width' => '14.14%']);
    $table->construct_header($lang->honeypot_ip_address, ['width' => '14.14%']);
    $table->construct_header($lang->honeypot_created_at, ['width' => '14.14%']);
    $table->construct_header($lang->honeypot_actions, ['width' => '2%']);

    $query = $db->simple_select("project_honeypot", "*", null, array('order_by' => 'created_at', 'order_dir' => 'DESC', 'limit_start' => $start, 'limit' => $perpage));
    while ($row = $db->fetch_array($query)) {
        $data = [
            'username' => htmlspecialchars_uni($row['username']),
            'email' => htmlspecialchars_uni($row['email']),
            'ip_address' => $row['ip_address'],
            'last_activity' => $row['last_activity']
                . " day" . ($row['last_activity'] != 0 && $row['last_activity'] > 1 ? 's' : '') . " ago",
            'threat_score' => $row['threat_score'],
            'visitor_type' => $row['visitor_type'],
            'created_at' => "<abbr title=\"" . date("jS M Y H:i", $row['created_at']) . "\">"
                . my_date('relative', $row['created_at']) . "</abbr>",
            'url' => 'https://www.projecthoneypot.org/ip_' . $row['ip_address']
        ];

        // Threat score colour code
        $style = '';
        if ($data['threat_score'] >= 50 && $data['threat_score'] < 75) {
            $style = 'color: #fff; background-color: #de9f2a;';
        } elseif ($data['threat_score'] >= 75) {
            $style = 'color: #fff; background-color: #ff5050;';
        }

        $table->construct_cell($data['username']);
        $table->construct_cell($data['email']);
        $table->construct_cell($data['last_activity']);
        $table->construct_cell($data['threat_score'], ['style' => $style]);
        $table->construct_cell($data['visitor_type']);
        $table->construct_cell($data['ip_address']);
        $table->construct_cell($data['created_at']);
        $table->construct_cell("<a href=\"" . $data['url'] . "\" target=\"_blank\"><img src=\"styles/{$page->style}/images/icons/find.png\" title=\"{$lang->honeypot_view}\" alt=\"{$lang->honeypot_view}\" /></a>");
        $table->construct_row();
    }

    if ($table->num_rows() == 0) {
        $table->construct_cell($lang->honeypot_no_logs, array("colspan" => "5"));
        $table->construct_row();
    }

    $table->output($lang->honeypot);

    // Do we need to construct the pagination?
    if ($rescount > $perpage) {
        echo draw_admin_pagination($pagecnt, $perpage, $rescount, "index.php?module=tools-honeypot&amp;perpage=" . $perpage);
    }

    $page->output_footer();
}
