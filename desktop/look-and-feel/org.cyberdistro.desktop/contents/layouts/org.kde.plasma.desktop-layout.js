/*
 * CyberDistro — default Plasma desktop layout (Plasma 6 scripting API).
 *
 * Applied by plasmashell on first start because /etc/xdg/kdeglobals selects
 * this look-and-feel package (LookAndFeelPackage=org.cyberdistro.desktop):
 * ShellCorona::loadDefaultLayout() uses <lnf>/contents/layouts/
 * org.kde.plasma.desktop-layout.js before falling back to the shell default.
 *
 * Layout (macOS-inspired, libre assets only):
 *   - top bar:    global menu · spacer · system tray · clock
 *   - bottom bar: app menu · [System Settings] [Security Center] [Files]
 *                 [Terminal] [Tor Browser] · running windows
 *
 * The Security Center launcher sits immediately to the right of System
 * Settings, at the bottom-left of the screen, as requested.
 */

var desktopsArray = desktopsForActivity(currentActivity());
for (var j = 0; j < desktopsArray.length; j++) {
    desktopsArray[j].wallpaperPlugin = "org.kde.image";
}

/* -------------------------------------------------------------- top bar */
var top = new Panel;
top.location = "top";
top.height = Math.round(gridUnit * 1.6);          /* ~28 px */
top.hiding = "none";
try { top.floating = false; } catch (e) {}

top.addWidget("org.kde.plasma.appmenu");          /* global menu */
top.addWidget("org.kde.plasma.panelspacer");
top.addWidget("org.kde.plasma.systemtray");
var clock = top.addWidget("org.kde.plasma.digitalclock");
clock.currentConfigGroup = ["Appearance"];
clock.writeConfig("showDate", true);
clock.writeConfig("dateFormat", "shortDate");

/* ----------------------------------------------------------- bottom bar */
var dock = new Panel;
dock.location = "bottom";
dock.height = Math.round(gridUnit * 2.6);         /* ~46 px */
dock.hiding = "none";
try { dock.floating = false; } catch (e) {}

var launcher = dock.addWidget("org.kde.plasma.kickoff");
launcher.currentConfigGroup = ["General"];
launcher.writeConfig("icon", "start-here-kde-symbolic");
launcher.writeConfig("favoritesPortedToKAstats", true);

var tasks = dock.addWidget("org.kde.plasma.icontasks");
tasks.currentConfigGroup = ["General"];
tasks.writeConfig("launchers", [
    "applications:systemsettings.desktop",            /* Impostazioni di sistema */
    "applications:cyberdistro-security-center.desktop", /* CyberDistro — Security Center */
    "preferred://filemanager",
    "applications:org.kde.konsole.desktop",
    "applications:cyberdistro-tor-browser.desktop"
]);
tasks.writeConfig("showOnlyCurrentDesktop", false);
tasks.writeConfig("groupingStrategy", 1);
tasks.writeConfig("iconSpacing", 1);

dock.addWidget("org.kde.plasma.panelspacer");
dock.addWidget("org.kde.plasma.showdesktop");
