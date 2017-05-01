# Project HoneyPot for MyBB

This MyBB plugin integrates Project HoneyPot into MyBB.

- Prevent users who hit a threat score threshold from registering on your forums.
- Ability to view full history logs in the 'Admin Control Panel'.

Currently, this plugin requires you to have a Project HoneyPot access key (which is free!).

## Installation

Firstly, you we need to get an access key from Project HoneyPot.
1. Head over to [Project HoneyPot](https://www.projecthoneypot.org/) and [create an account](https://www.projecthoneypot.org/create_account.php).
2. Next, you will need to go to the "[Manage HTTP Blacklist](https://www.projecthoneypot.org/httpbl_configure.php)" page and generate a http:BL access key.

Now that you have an access you, you can install this plugin.
1. Merging all the folders and files in the "UPLOAD" directory to your root directory of your MyBB installation. This process *should not* override any existing files.
2. After installing this plugin, head over to your MyBB "Admin Control Panel" and navigate to "Configuration" -> "Plugins". On this page, you should see the "Project HoneyPot for MyBB" under the "Inactive Plugins" list. Click "Install & Activate".
3. Now, head back to the "Configuration" page and scroll to the bottom of the page to find the "Project HoneyPot" settings under "Plugin Settings". On this page you will need to enter your access key; you can also configure your threat level threshold on this page too.

You now have Project HoneyPot installed on your MyBB installation.


## Usage

If you have entered a valid access key and threat level, this plugin will automatically prevent any users who hit your threat level threshold from registering on your forums.

You can see all of this plugins activities on the Project HoneyPot logs, which are located under "Tools & Maintenance", in the "Logs" sub-menu.

## Credits

- Project HoneyPot - [https://www.projecthoneypot.org](https://www.projecthoneypot.org)
- MyBB - [https://mybb.com](https://mybb.com)
- Jamie Sage - [https://www.jamiesage.co.uk](https://www.jamiesage.co.uk)

## License

[MIT License](https://github.com/jamiesage123/Project-HoneyPot-for-MyBB/blob/master/LICENSE)
