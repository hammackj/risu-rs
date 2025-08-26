// Auto-generated from Ruby postprocess definitions
use super::{PluginEntry, PostProcess, PostProcessInfo};
use crate::models::{Item, Plugin};
use crate::parser::NessusReport;

fn run_rollup(
    report: &mut NessusReport,
    plugin_id: i32,
    plugin_name: &str,
    item_name: &str,
    description: &str,
    plugin_ids: &[i32],
) {
    let mut found = false;
    let mut max_sev = 0;
    for item in &mut report.items {
        if let Some(pid) = item.plugin_id {
            if plugin_ids.contains(&pid) {
                found = true;
                if let Some(sev) = item.severity {
                    if sev > max_sev {
                        max_sev = sev;
                    }
                }
                item.real_severity = item.severity;
                item.severity = Some(-1);
            }
        }
    }
    if !found {
        return;
    }
    let mut plugin = Plugin::default();
    plugin.plugin_id = Some(plugin_id);
    plugin.plugin_name = Some(plugin_name.to_string());
    plugin.family_name = Some("Risu Rollup Plugins".to_string());
    plugin.description = Some(description.to_string());
    plugin.plugin_type = Some("Rollup".to_string());
    plugin.rollup = Some(true);
    report.plugins.push(plugin);
    let mut item = Item::default();
    item.plugin_id = Some(plugin_id);
    item.plugin_name = Some(item_name.to_string());
    item.severity = Some(max_sev);
    report.items.push(item);
}

struct Plugin7zip;

impl PostProcess for Plugin7zip {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "7zip",
            order: 1000,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99954,
            "Missing the latest 7-Zip Patches",
            "Update to the latest 7-Zip",
            "7-Zip Patch Rollup",
            PLUGIN_IDS_P7ZIP,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Plugin7zip }
}

const PLUGIN_IDS_P7ZIP: &[i32] = &[
    91230, 109730, 109799, 109800, 180360, 211725, 214542, 209231,
];

struct AdobeAcrobat;

impl PostProcess for AdobeAcrobat {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "adobe_acrobat",
            order: 1001,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99975,
            "Missing the latest Adobe Acrobat Patches",
            "Update to the latest Adobe Acrobat",
            "Adobe Acrobat Patch Rollup",
            PLUGIN_IDS_ADOBE_ACROBAT,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &AdobeAcrobat }
}

const PLUGIN_IDS_ADOBE_ACROBAT: &[i32] = &[
    79855, 83470, 40803, 40804, 40805, 40806, 42119, 43875, 44643, 45504, 47164, 48374, 49172,
    50613, 51924, 52671, 53450, 55143, 56197, 57042, 77813, 57483, 58682, 61561, 64785, 63453,
    66409, 74011, 84801, 84800, 77176, 77711, 69845, 71946, 86402, 91096, 87917, 89830, 92034,
    40802, 40801, 40800, 96452, 99373, 94071, 102427, 169877, 174136, 163958, 166041, 179482,
    181274, 190457, 212261,
];

struct AdobeAir;

impl PostProcess for AdobeAir {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "adobe_air",
            order: 1002,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99994,
            "Missing the latest Adobe Air Patches",
            "Update to the latest Adobe Air",
            "Adobe Air Patch Rollup",
            PLUGIN_IDS_ADOBE_AIR,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &AdobeAir }
}

const PLUGIN_IDS_ADOBE_AIR: &[i32] = &[
    56959, 52755, 53474, 55805, 66444, 66871, 69865, 70214, 70857, 71350, 71950, 73432, 73993,
    74430, 73432, 73993, 74430, 58537, 59425, 61624, 62835, 62479, 63449, 64583, 65218, 65909,
    66444, 66871, 63241, 77171, 77576, 78440, 79139, 80483, 34815, 40447, 43069, 46858, 48299,
    50604, 44595, 84155, 84156, 84157, 84158, 84641, 85325, 86059, 86368, 86850, 87243, 87656,
    88638, 89868, 91162, 93523,
];

struct AdobeColdfusion;

impl PostProcess for AdobeColdfusion {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "adobe_coldfusion",
            order: 1003,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99950,
            "Missing the latest Adobe Coldfusion Patches",
            "Update to the latest Adobe Coldfusion",
            "Adobe Coldfusion Patch Rollup",
            PLUGIN_IDS_ADOBE_COLDFUSION,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &AdobeColdfusion }
}

const PLUGIN_IDS_ADOBE_COLDFUSION: &[i32] = &[64689, 72091, 99731];

struct AdobeCreativeDesktop;

impl PostProcess for AdobeCreativeDesktop {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "adobe_creative_desktop",
            order: 1004,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99948,
            "Missing the latest Adobe Creative Cloud Desktop Patches",
            "Update to the latest Adobe Creative Cloud Desktop",
            "Adobe Creative Cloud Desktop Patch Rollup",
            PLUGIN_IDS_ADOBE_CREATIVE_DESKTOP,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &AdobeCreativeDesktop }
}

const PLUGIN_IDS_ADOBE_CREATIVE_DESKTOP: &[i32] = &[99366, 91386, 94055];

struct AdobeFlashPlayer;

impl PostProcess for AdobeFlashPlayer {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "adobe_flash_player",
            order: 1005,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99997,
            "Missing the latest Adobe Flash Player Patches",
            "Update to the latest Adobe Flash Player",
            "Adobe Flash Player Patch Rollup",
            PLUGIN_IDS_ADOBE_FLASH_PLAYER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &AdobeFlashPlayer }
}

const PLUGIN_IDS_ADOBE_FLASH_PLAYER: &[i32] = &[
    100756, 11323, 11952, 20158, 21079, 22056, 23869, 25694, 29741, 31799, 34741, 35742, 40434,
    43068, 44596, 46859, 48300, 49307, 50493, 51926, 52673, 53472, 54299, 54972, 55140, 55803,
    56259, 56874, 58001, 58207, 58538, 58994, 59426, 61550, 61622, 62480, 62836, 63242, 63450,
    64506, 64584, 64916, 65219, 65910, 66445, 66872, 67225, 69866, 70858, 71351, 71951, 72284,
    72606, 72937, 73433, 73740, 73994, 74431, 76413, 77172, 77577, 78441, 79140, 79442, 79835,
    80484, 80946, 80998, 81127, 81819, 82781, 83365, 84048, 84365, 84642, 84730, 85326, 86060,
    86369, 86423, 86851, 87244, 87657, 88639, 89834, 90425, 91163, 91670, 92012, 93461, 93960,
    94334, 94628, 95762, 96388, 97142, 97727, 99283, 100052, 102262, 101362, 103124, 103922,
    108958, 104544, 105691, 106606, 108281, 109601, 105175, 110397, 111683, 110979, 119094, 119462,
    123938, 125056, 125815, 125827, 125068, 104547, 105693, 106655, 108287, 118909, 122117, 117419,
    118917, 122130, 128633, 117410, 133607, 137253, 141494,
];

struct AdobeReader;

impl PostProcess for AdobeReader {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "adobe_reader",
            order: 1006,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99998,
            "Missing the latest Adobe Reader Patches",
            "Update to the latest Adobe Reader",
            "Adobe Reader Patch Rollup",
            PLUGIN_IDS_ADOBE_READER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &AdobeReader }
}

const PLUGIN_IDS_ADOBE_READER: &[i32] = &[
    71947, 30200, 33256, 34695, 35821, 38746, 39355, 42120, 43876, 44644, 45505, 47165, 48375,
    49173, 50614, 51925, 55144, 56198, 74012, 58683, 61562, 63454, 64786, 66410, 69846, 71947,
    57043, 57484, 24002, 23776, 23975, 52672, 53451, 21698, 77712, 79856, 77175, 83471, 40494,
    27584, 86403, 87918, 89831, 70343, 91097, 92035, 94072, 96453, 99374, 102428, 104627, 104626,
    111794, 117600, 117877, 106846, 109896, 111012, 119676, 120952, 122253, 122368, 117876, 120951,
    122252, 122367, 119675, 125222, 127904, 124008, 118932, 142467, 156668, 159657, 129978, 132037,
    133673, 134706, 146422, 149379, 151586, 185552, 185553, 139581, 163033, 163955, 169880, 181276,
    174135, 179484, 166043, 150341, 153364, 144107, 197027,
];

struct AdobeShockwavePlayer;

impl PostProcess for AdobeShockwavePlayer {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "adobe_shockwave_player",
            order: 1007,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99991,
            "Missing the latest Adobe Shockwave Player Patches",
            "Update to the latest Adobe Shockwave Player",
            "Adobe Shockwave Player Patch Rollup",
            PLUGIN_IDS_ADOBE_SHOCKWAVE_PLAYER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &AdobeShockwavePlayer }
}

const PLUGIN_IDS_ADOBE_SHOCKWAVE_PLAYER: &[i32] = &[
    72435, 72983, 42369, 51936, 71342, 44094, 39564, 40421, 44094, 46329, 48436, 50387, 55142,
    55833, 56734, 57941, 59047, 61536, 62702, 64621, 65913, 67233, 69844, 84765, 85882, 86633,
    97835, 100806, 104628, 124028,
];

struct Apache;

impl PostProcess for Apache {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "apache",
            order: 1008,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99986,
            "Missing the latest Apache patches",
            "Update to the latest Apache",
            "Apache Patch Rollup",
            PLUGIN_IDS_APACHE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Apache }
}

const PLUGIN_IDS_APACHE: &[i32] = &[
    11030, 11137, 11793, 11915, 31654, 55976, 57792, 12280, 17696, 31408, 73405, 56216, 57791,
    62101, 64912, 68915, 77531, 45004, 57603, 42052, 48205, 50070, 53896, 69014, 76622, 81126,
    73081, 84959, 40467, 96451, 100995, 101788, 103838, 101787, 68914, 123642, 139574, 150280,
    111788, 117807, 121355, 122060, 128033, 92320, 135290, 150244, 153584, 156255, 153583, 153585,
    153586, 158900, 161948, 161454, 170113, 172186, 183391, 192923, 201198, 202577, 193421, 193419,
    193422, 193423, 193424, 193420, 210450,
];

struct ApacheLog4j;

impl PostProcess for ApacheLog4j {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "apache_log4j",
            order: 1009,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99930,
            "Missing the latest Apache Log4j",
            "Update to the latest Apache Log4j",
            "Apache Log4j Patch Rollup",
            PLUGIN_IDS_APACHE_LOG4J,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &ApacheLog4j }
}

const PLUGIN_IDS_APACHE_LOG4J: &[i32] = &[156002, 156327, 156860, 156057, 156183, 156103, 182252];

struct ApacheTomcat;

impl PostProcess for ApacheTomcat {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "apache_tomcat",
            order: 1010,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99966,
            "Missing the latest Apache Tomcat Patches",
            "Update to the latest Apache Tomcat",
            "Apache Tomcat Patch Rollup",
            PLUGIN_IDS_APACHE_TOMCAT,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &ApacheTomcat }
}

const PLUGIN_IDS_APACHE_TOMCAT: &[i32] = &[
    81649, 12085, 35806, 81650, 83526, 70414, 134862, 133845, 111066, 141446, 144050, 147164,
    118036, 132413, 132418, 136807, 138097, 138574, 144054, 147019, 152183, 126125, 56070, 72692,
    95438, 121119, 62985, 62988, 63200, 66427, 66428, 72691, 74246, 103329, 103698, 103782, 106975,
    121116, 121117, 121118, 121120, 136770, 147163, 148405, 77475, 83764, 88936, 94578, 96003,
    99367, 100681, 55859, 57082, 57541, 151502, 152182, 160894, 162498, 102587, 118035, 121121,
    124064, 166807, 169458, 162502, 166906, 171657, 173251, 180194, 159464, 171351, 74247, 83490,
    72690, 74245, 81579, 171656, 186364, 173256, 180192, 182811, 197843, 197848, 197818, 197820,
    197823, 197831, 197838, 213078, 232528, 235034, 157117, 186365, 201848, 237498, 240060, 241680,
    182809, 192042, 194473, 197830,
];

struct AppleIcloud;

impl PostProcess for AppleIcloud {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "apple_icloud",
            order: 1011,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99939,
            "Missing the latest Apple iCloud",
            "Update to the latest Apple iCloud",
            "Apple iCloud Patch Rollup",
            PLUGIN_IDS_APPLE_ICLOUD,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &AppleIcloud }
}

const PLUGIN_IDS_APPLE_ICLOUD: &[i32] = &[125878];

struct AppleItunes;

impl PostProcess for AppleItunes {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "apple_itunes",
            order: 1012,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99960,
            "Missing the latest Apple iTunes Patches",
            "Update to the latest Apple iTunes",
            "Apple iTunes Patch Rollup",
            PLUGIN_IDS_APPLE_ITUNES,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &AppleItunes }
}

const PLUGIN_IDS_APPLE_ITUNES: &[i32] = &[
    84504, 86001, 86602, 91347, 87371, 92410, 94914, 94915, 95824, 96830, 100025, 100300, 78597,
    101954, 111105, 117880, 108795, 110384, 118718, 119767, 121473,
];

struct AppleQuicktime;

impl PostProcess for AppleQuicktime {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "apple_quicktime",
            order: 1013,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99973,
            "Missing the latest Apple QuickTime Patches",
            "Update to the latest Apple QuickTime",
            "Apple QuickTime Patch Rollup",
            PLUGIN_IDS_APPLE_QUICKTIME,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &AppleQuicktime }
}

const PLUGIN_IDS_APPLE_QUICKTIME: &[i32] = &[
    48323, 49260, 51062, 66636, 72706, 78678, 62890, 87848, 85662, 84505, 59113, 56667, 55764,
    21556, 22336, 24761, 25123, 25347, 25703, 26916, 29698, 29982, 31735, 33130, 34119, 35437,
    38988, 40929, 45388, 27626, 30204, 11506, 17637, 20136, 20395,
];

struct ArtifexGhostscript;

impl PostProcess for ArtifexGhostscript {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "artifex_ghostscript",
            order: 1014,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99937,
            "Missing the latest Artifex Ghostscript",
            "Update to the latest Artifex Ghostscript",
            "Artifex Ghostscript Patch Rollup",
            PLUGIN_IDS_ARTIFEX_GHOSTSCRIPT,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &ArtifexGhostscript }
}

const PLUGIN_IDS_ARTIFEX_GHOSTSCRIPT: &[i32] = &[
    117459, 117596, 119240, 130273, 177205, 177836, 186904, 200487, 210946,
];

struct BlackberryEnterpriseServer;

impl PostProcess for BlackberryEnterpriseServer {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "blackberry_enterprise_server",
            order: 1015,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99968,
            "Missing the latest Black Berry Enterprise Server Patches",
            "Update to the latest Black Berry Enterprise Server",
            "Black Berry Enterprise Server Patch Rollup",
            PLUGIN_IDS_BLACKBERRY_ENTERPRISE_SERVER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &BlackberryEnterpriseServer }
}

const PLUGIN_IDS_BLACKBERRY_ENTERPRISE_SERVER: &[i32] =
    &[50071, 51191, 51527, 55819, 55670, 53829, 72583, 77327];

struct CaBrightstorArcserve;

impl PostProcess for CaBrightstorArcserve {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "ca_brightstor_arcserve",
            order: 1016,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99982,
            "Missing the latest CA BrightStor ARCserve Backup Patches",
            "Update to the latest CA BrightStor ARCserve Backup",
            "CA BrightStor ARCserve Backup Patch Rollup",
            PLUGIN_IDS_CA_BRIGHTSTOR_ARCSERVE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &CaBrightstorArcserve }
}

const PLUGIN_IDS_CA_BRIGHTSTOR_ARCSERVE: &[i32] =
    &[24015, 24816, 25086, 26970, 32398, 34393, 22510, 23841];

struct CiscoAnyconnect;

impl PostProcess for CiscoAnyconnect {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "cisco_anyconnect",
            order: 1017,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99961,
            "Missing the latest Cisco AnyConnect Client Patches",
            "Update to the latest Cisco AnyConnect Client",
            "Cisco AnyConnect Client Patch Rollup",
            PLUGIN_IDS_CISCO_ANYCONNECT,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &CiscoAnyconnect }
}

const PLUGIN_IDS_CISCO_ANYCONNECT: &[i32] = &[
    76491, 81978, 86302, 78676, 81671, 82270, 85266, 85267, 85541, 87894, 88100, 54954, 59820,
    93382, 71464, 95951, 100790, 139411, 144945, 149448, 110563, 134164, 148450, 150811,
];

struct CiscoIos;

impl PostProcess for CiscoIos {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "cisco_ios",
            order: 1018,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99965,
            "Missing the latest Cisco IOS Patches",
            "Update to the latest Cisco IOS",
            "Cisco IOS Patch Rollup",
            PLUGIN_IDS_CISCO_IOS,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &CiscoIos }
}

const PLUGIN_IDS_CISCO_IOS: &[i32] = &[
    58568, 58570, 58572, 62372, 62373, 65891, 70316, 70322, 73345, 78035, 82571, 90358, 99028,
    99687, 103670, 97991, 94252, 103565, 108722, 108880, 108956, 109087, 117944, 108720, 133000,
    103669, 103693, 117949, 129694, 132048, 132723, 137630, 137654, 129812, 130092, 131325, 141170,
    130766, 131164, 131322, 184452,
];

struct CiscoTelepresence;

impl PostProcess for CiscoTelepresence {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "cisco_telepresence",
            order: 1019,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99941,
            "Missing the latest Cisco Telepresence",
            "Update to the latest Cisco Telepresence",
            "Cisco Telepresence Patch Rollup",
            PLUGIN_IDS_CISCO_TELEPRESENCE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &CiscoTelepresence }
}

const PLUGIN_IDS_CISCO_TELEPRESENCE: &[i32] = &[100838];

struct CiscoWirelessLanController;

impl PostProcess for CiscoWirelessLanController {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "cisco_wireless_lan_controller",
            order: 1020,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99919,
            "Missing the latest Cisco Wireless LAN Controller",
            "Update to the latest Cisco Wireless LAN Controller",
            "Cisco Wireless LAN Controller Patch Rollup",
            PLUGIN_IDS_CISCO_WIRELESS_LAN_CONTROLLER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &CiscoWirelessLanController }
}

const PLUGIN_IDS_CISCO_WIRELESS_LAN_CONTROLLER: &[i32] = &[
    118461, 130208, 138440, 139036, 141369, 192919, 94108, 99471, 124331, 124332, 124333, 124334,
];

struct CoreFtp;

impl PostProcess for CoreFtp {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "core_ftp",
            order: 1021,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99989,
            "Missing the latest CoreFTP Patches",
            "Update to the latest CoreFTP",
            "CoreFTP Patch Rollup",
            PLUGIN_IDS_CORE_FTP,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &CoreFtp }
}

const PLUGIN_IDS_CORE_FTP: &[i32] = &[65789, 70656, 59243];

struct Db2;

impl PostProcess for Db2 {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "db2",
            order: 1022,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99980,
            "Missing the latest DB2 Patches",
            "Update to the latest DB2",
            "DB2 Patch Rollup",
            PLUGIN_IDS_DB2,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Db2 }
}

const PLUGIN_IDS_DB2: &[i32] = &[62701, 71519, 76114, 76116, 84828];

struct DellBios;

impl PostProcess for DellBios {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "dell_bios",
            order: 1023,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99918,
            "Missing the latest Dell Client BIOS",
            "Update to the latest Dell Client BIOS",
            "Dell Client BIOS Patch Rollup",
            PLUGIN_IDS_DELL_BIOS,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &DellBios }
}

const PLUGIN_IDS_DELL_BIOS: &[i32] = &[165181, 216935];

struct DellIdrac;

impl PostProcess for DellIdrac {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "dell_idrac",
            order: 1024,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99947,
            "Missing the latest Dell iDRAC Patches",
            "Update to the latest Dell iDRAC",
            "Dell iDRAC Products Patch Rollup",
            PLUGIN_IDS_DELL_IDRAC,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &DellIdrac }
}

const PLUGIN_IDS_DELL_IDRAC: &[i32] = &[
    109208, 111604, 119833, 90265, 135187, 162428, 159643, 161798, 167508, 167509, 131730, 139206,
    144756, 148956, 161800, 70411, 80442, 193888, 202259, 148955, 161799,
];

struct DropbearSsh;

impl PostProcess for DropbearSsh {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "dropbear_ssh",
            order: 1025,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99952,
            "Missing the latest Dropbear SSH Server Patches",
            "Update to the latest Dropbear SSH Server",
            "Dropbear SSH Server Patch Rollup",
            PLUGIN_IDS_DROPBEAR_SSH,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &DropbearSsh }
}

const PLUGIN_IDS_DROPBEAR_SSH: &[i32] = &[93650, 58183, 70545, 21023, 34769];

struct Filezilla;

impl PostProcess for Filezilla {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "filezilla",
            order: 1026,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99974,
            "Missing the latest FileZilla Client Patches",
            "Update to the latest FileZilla Client",
            "FileZilla Client Patch Rollup",
            PLUGIN_IDS_FILEZILLA,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Filezilla }
}

const PLUGIN_IDS_FILEZILLA: &[i32] = &[69476, 69494];

struct Firefox;

impl PostProcess for Firefox {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "firefox",
            order: 1027,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99972,
            "Missing the latest Firefox Patches",
            "Update to the latest Firefox",
            "Firefox Patch Rollup",
            PLUGIN_IDS_FIREFOX,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Firefox }
}

const PLUGIN_IDS_FIREFOX: &[i32] = &[
    73099, 73769, 74440, 76763, 77500, 77906, 78473, 79665, 80523, 81521, 82040, 82041, 82503,
    82998, 83439, 84581, 82583, 85386, 62998, 63551, 64723, 65131, 65806, 66480, 66993, 69269,
    69993, 70716, 70949, 71347, 72331, 85275, 85689, 86071, 86764, 87476, 86418, 88461, 89875,
    90793, 91547, 88754, 92755, 93662, 94960, 95475, 95886, 96776, 97639, 99125, 99632, 100127,
    55901, 56334, 56750, 57768, 57769, 58006, 58349, 58898, 59407, 60043, 61715, 62580, 62589,
    94232, 102359, 100810, 103680, 99631, 100126, 100809, 102358, 104637, 105212, 106302, 103679,
    108376, 108586, 108755, 104638, 105213, 106303, 106561, 108377, 108587, 108756, 109869, 105040,
    105616, 110811, 117294, 118397, 117921, 117941, 122948, 123012, 121512, 125361, 126002, 126072,
    121477, 109868, 110809, 125877, 117668, 119604, 122233, 126622, 128061, 128525, 132715, 133693,
    136404, 135276, 137049, 138085, 138445, 119606, 134405, 134407, 139040, 139789, 142613, 142910,
    141571, 131773, 132709, 135202, 129101, 130170, 140732, 144282, 146425, 150119, 148767, 151571,
    152412, 152635, 150802, 153089, 153881, 154819, 148014, 149281, 158654, 158694, 157443, 160465,
    161415, 161716, 162602, 155917, 156606, 159530, 163497, 164344, 165262, 166209, 167633, 168651,
    170099, 177932, 174076, 175330, 176741, 171454, 172515, 178147, 180232, 181349, 181875, 182134,
    179143, 186186, 183784, 189364, 190779, 192470, 193366, 196992, 200315, 183785, 186030, 186032,
    187079, 205009, 202017, 192243,
];

struct Flexnet;

impl PostProcess for Flexnet {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "flexnet",
            order: 1028,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99987,
            "Missing the latest Macrovision FLEXnet Patches",
            "Update to the latest Macrovision FLEXnet",
            "Macrovision FLEXnet Patch Rollup",
            PLUGIN_IDS_FLEXNET,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Flexnet }
}

const PLUGIN_IDS_FLEXNET: &[i32] = &[25371, 24712, 27599, 128148];

struct Foxit3d;

impl PostProcess for Foxit3d {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "foxit_3d",
            order: 1029,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99934,
            "Missing the latest Foxit 3D Plugin",
            "Update to the latest Foxit 3D Plugin",
            "Foxit 3D Plugin Patch Rollup",
            PLUGIN_IDS_FOXIT_3D,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Foxit3d }
}

const PLUGIN_IDS_FOXIT_3D: &[i32] = &[132633, 139233];

struct FoxitPhantomPdf;

impl PostProcess for FoxitPhantomPdf {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "foxit_phantom_pdf",
            order: 1030,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99956,
            "Missing the latest Foxit PhantomPDF Patches",
            "Update to the latest Foxit PhantomPDF",
            "Foxit PhantomPDF Patch Rollup",
            PLUGIN_IDS_FOXIT_PHANTOM_PDF,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &FoxitPhantomPdf }
}

const PLUGIN_IDS_FOXIT_PHANTOM_PDF: &[i32] = &[
    86697, 90566, 102682, 102858, 101523, 104436, 104742, 109398, 119258, 119259, 119835, 119836,
    133525, 141216,
];

struct FoxitReader;

impl PostProcess for FoxitReader {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "foxit_reader",
            order: 1031,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99969,
            "Missing the latest Foxit Reader Patches",
            "Update to the latest Foxit Reader",
            "Foxit Reader Patch Rollup",
            PLUGIN_IDS_FOXIT_READER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &FoxitReader }
}

const PLUGIN_IDS_FOXIT_READER: &[i32] = &[
    52458, 55671, 57050, 62063, 62384, 72723, 62064, 86698, 90567, 101524, 112059, 131078, 135849,
];

struct GoogleChrome;

impl PostProcess for GoogleChrome {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "google_chrome",
            order: 1032,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99990,
            "Missing the latest Google Chrome Patches",
            "Update to the latest Google Chrome",
            "Google Chrome Patch Rollup",
            PLUGIN_IDS_GOOGLE_CHROME,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &GoogleChrome }
}

const PLUGIN_IDS_GOOGLE_CHROME: &[i32] = &[
    74434, 76581, 80485, 80951, 81020, 81207, 81647, 82534, 82825, 83136, 83366, 83745, 84049,
    84667, 84731, 84921, 77409, 77581, 77861, 78080, 78475, 79141, 79336, 79578, 79836, 84342,
    77184, 85567, 85743, 86061, 86209, 86380, 86598, 86852, 87206, 87245, 87417, 88088, 88681,
    90794, 88956, 89685, 89786, 90194, 90542, 73419, 74008, 70916, 70923, 72167, 72939, 66813,
    62313, 62519, 63110, 63232, 63468, 63645, 73710, 74122, 71227, 71968, 72616, 72800, 73082,
    67232, 69139, 69423, 70273, 70494, 66556, 66930, 91128, 91350, 91455, 61381, 61462, 61774,
    62518, 62861, 63063, 64813, 65029, 65097, 93315, 92628, 92791, 59117, 59255, 59735, 59958,
    91716, 93476, 93817, 99633, 99995, 94136, 94580, 94676, 95480, 96828, 97724, 99136, 100679,
    100991, 101980, 102993, 103933, 105356, 106350, 105152, 104434, 103421, 106485, 106840, 107220,
    110228, 109395, 109899, 111383, 117333, 117429, 118153, 117636, 122853, 121514, 118887, 119097,
    119558, 122246, 122617, 124279, 124460, 125371, 125952, 133465, 133848, 139001, 139459, 136348,
    138449, 131022, 134701, 142971, 143471, 148558, 150430, 154238, 158500, 158936, 159304, 159638,
    160217, 160906, 161477, 161979, 162422, 162706, 163273, 163724, 164155, 164508, 165068, 165502,
    165590, 139695, 139794, 142641, 144781, 159235, 159494, 159741, 166045, 146948, 136743, 137081,
    137635, 137701, 140406, 140700, 141194, 141573, 142209, 142719, 145071, 146060, 146204, 146544,
    147754, 148243, 148487, 148848, 148996, 149412, 149900, 150854, 151672, 151831, 152189, 152609,
    152928, 153255, 153515, 153630, 153829, 153931, 154706, 155352, 155867, 156033, 156462, 156862,
    157293, 158051, 164656, 166631, 166468, 167101, 171321, 168273, 168699, 168701, 169758, 170519,
    168372, 168181, 172221, 173059, 173836, 174332, 174478, 175001, 175839, 176494, 176496, 176675,
    177227, 177635, 178447, 179224, 179837, 180163, 180250, 180508, 181235, 181291, 182072, 182442,
    182850, 183806, 184083, 185349, 185587, 186362, 185605, 183246, 186834, 186835, 187132, 187134,
    187619, 187620, 188158, 188161, 189460, 189823, 190064, 190441, 191060, 186600, 190813, 200329,
    210778, 216177, 214952, 233671,
];

struct HpSystemMgtHomepage;

impl PostProcess for HpSystemMgtHomepage {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "hp_system_mgt_homepage",
            order: 1033,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99985,
            "Missing the latest HP System Management Homepage Patches",
            "Update to the latest HP System Management Homepage",
            "HP System Management Homepage Patch Rollup",
            PLUGIN_IDS_HP_SYSTEM_MGT_HOMEPAGE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &HpSystemMgtHomepage }
}

const PLUGIN_IDS_HP_SYSTEM_MGT_HOMEPAGE: &[i32] = &[
    53532, 58811, 59851, 66541, 69020, 70118, 76345, 49272, 72959, 46015, 46677, 78090, 33548,
    34694, 38832, 85181, 84923, 73639, 90150, 90251, 91222, 94654, 103530,
];

struct Ilo;

impl PostProcess for Ilo {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "iLo",
            order: 1034,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99942,
            "Missing the latest iLO Patches",
            "Update to the latest iLO Patches",
            "iLO Patch Rollup",
            PLUGIN_IDS_ILO,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Ilo }
}

const PLUGIN_IDS_ILO: &[i32] = &[
    122032, 125342, 122095, 122187, 122191, 102803, 134976, 140770, 162139,
];

struct IntelMgtEngine;

impl PostProcess for IntelMgtEngine {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "intel_mgt_engine",
            order: 1035,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99951,
            "Missing the latest Intel Management Engine Patches",
            "Update to the latest Intel Management Engine",
            "Intel Management Engine Patch Rollup",
            PLUGIN_IDS_INTEL_MGT_ENGINE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &IntelMgtEngine }
}

const PLUGIN_IDS_INTEL_MGT_ENGINE: &[i32] = &[97998, 97999, 97997];

struct Irfanview;

impl PostProcess for Irfanview {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "irfanview",
            order: 1036,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99958,
            "Missing the latest IrfanView Patches",
            "Update to the latest IrfanView",
            "IrfanView Patch Rollup",
            PLUGIN_IDS_IRFANVIEW,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Irfanview }
}

const PLUGIN_IDS_IRFANVIEW: &[i32] = &[68888, 72395];

struct Java;

impl PostProcess for Java {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "java",
            order: 1037,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99999,
            "Missing the latest Java Patches",
            "Update to the latest Java",
            "Java Patch Rollup",
            PLUGIN_IDS_JAVA,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Java }
}

const PLUGIN_IDS_JAVA: &[i32] = &[
    66932, 65995, 59462, 62593, 45544, 45379, 65050, 63521, 65052, 49996, 52002, 54997, 55958,
    56566, 57290, 57959, 64454, 64790, 76532, 73570, 70472, 71966, 61746, 42373, 36034, 40495,
    23931, 25370, 24022, 26923, 35030, 31356, 65048, 33488, 78481, 80908, 82820, 25124, 25627,
    25903, 31344, 33487, 25693, 30148, 61681, 84824, 33486, 25709, 86542, 88045, 90625, 90828,
    92516, 92516, 99588, 94138, 96628, 101843, 103963, 30149, 106190, 109202, 111163, 118228,
    121231, 124198, 126821, 130011, 135592, 138522, 132992, 145218, 141800, 148960, 152020, 154344,
    156887, 159975, 166316, 163304, 170161, 174511, 178485, 189116, 193574, 202704, 183295, 209282,
    214532, 161241, 234624,
];

struct Jquqery;

impl PostProcess for Jquqery {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "jquqery",
            order: 1038,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99916,
            "Missing the latest JQuery",
            "Update to the latest JQuery",
            "JQuery Patch Rollup",
            PLUGIN_IDS_JQUQERY,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Jquqery }
}

const PLUGIN_IDS_JQUQERY: &[i32] = &[136929];

struct Libreoffice;

impl PostProcess for Libreoffice {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "libreoffice",
            order: 1039,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99962,
            "Missing the latest LibreOffice Patches",
            "Update to the latest LibreOffice",
            "LibreOffice Patch Rollup",
            PLUGIN_IDS_LIBREOFFICE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Libreoffice }
}

const PLUGIN_IDS_LIBREOFFICE: &[i32] = &[
    80078, 86900, 88983, 86901, 80832, 73336, 91974, 97496, 127114, 129535, 133474, 122586, 122588,
    122857, 125223, 133471, 163762, 163764, 197300,
];

struct MicrosoftAzureDataStudio;

impl PostProcess for MicrosoftAzureDataStudio {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "microsoft_azure_data_studio",
            order: 1040,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99920,
            "Missing the latest Microsoft Azure Data Studio",
            "Update to the latest Microsoft Azure Data Studio",
            "Microsoft Azure Data Studio Patch Rollup",
            PLUGIN_IDS_MICROSOFT_AZURE_DATA_STUDIO,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MicrosoftAzureDataStudio }
}

const PLUGIN_IDS_MICROSOFT_AZURE_DATA_STUDIO: &[i32] = &[192147];

struct MicrosoftDotNet;

impl PostProcess for MicrosoftDotNet {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "microsoft_dot_net",
            order: 1041,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99925,
            "Missing the latest Microsoft .NET",
            "Update to the latest Microsoft .NET",
            "Microsoft .NET Patch Rollup",
            PLUGIN_IDS_MICROSOFT_DOT_NET,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MicrosoftDotNet }
}

const PLUGIN_IDS_MICROSOFT_DOT_NET: &[i32] = &[
    209021, 193217, 179664, 174219, 185886, 150365, 150708, 152488, 156227, 157879, 158744, 161167,
    177265, 178193, 167254, 167885, 168395, 168396, 168397, 179502, 181277, 183025, 168747, 171545,
    202031, 147946, 190535, 133049, 185887, 177393, 168745, 169775, 168398, 208286, 202304, 208757,
    171598, 141503, 187859, 193142, 136564, 138464, 214274, 232619, 232847, 234051,
];

struct MicrosoftEdge;

impl PostProcess for MicrosoftEdge {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "microsoft_edge",
            order: 1042,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99924,
            "Missing the latest Microsoft Edge",
            "Update to the latest Microsoft Edge",
            "Microsoft Edge Patch Rollup",
            PLUGIN_IDS_MICROSOFT_EDGE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MicrosoftEdge }
}

const PLUGIN_IDS_MICROSOFT_EDGE: &[i32] = &[
    162168, 157881, 159239, 159592, 162624, 161989, 162503, 162776, 157369, 158097, 207516, 207866,
    202635, 204747, 204961, 205697, 206172, 208101, 208710, 171268, 205222, 158583, 159037, 159465,
    159816, 161198, 161717, 160319, 186447,
];

struct MicrosoftOffice;

impl PostProcess for MicrosoftOffice {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "microsoft_office",
            order: 1043,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99946,
            "Missing the latest Microsoft Office Patches",
            "Update to the latest Microsoft Office",
            "Microsoft Office Patch Rollup",
            PLUGIN_IDS_MICROSOFT_OFFICE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MicrosoftOffice }
}

const PLUGIN_IDS_MICROSOFT_OFFICE: &[i32] = &[
    22031, 22032, 22033, 31046, 31047, 31413, 31414, 31415, 91611, 92019, 92839, 125071, 125072,
    125832, 118926, 96391, 126580, 126583, 127853, 108976, 110492, 122128, 126585, 127854, 127856,
    128645, 128648, 108293, 130913, 129727, 131937, 131938, 131940, 130911, 132867, 133616, 135474,
    135476, 135482, 136511, 52584, 56176, 139497, 139499, 139505, 138602, 139598, 134382, 137264,
    141418, 141428, 142685, 142689, 143555, 143564, 143567, 144875, 144885, 147218, 110496, 156628,
    156630, 131935, 132869, 133622, 135462, 135478, 135479, 137267, 137272, 138470, 138474, 139507,
    140426, 140430, 140433, 141415, 141417, 143563, 144879, 146336, 147216, 147225, 148464, 148470,
    148474, 148478, 149397, 149399, 149401, 150351, 150356, 150371, 151590, 151595, 151609, 153380,
    153387, 154027, 154031, 154038, 154982, 155000, 156062, 156074, 156631, 157433, 157441, 158705,
    159673, 159683, 111756, 142688, 171554, 171556, 172527, 177245, 178162, 178165, 163950, 172522,
    172537, 174114, 160940, 163944, 164993, 166037, 167108, 167110, 177248, 178169, 175337, 175346,
    175408, 171449, 172607, 178203, 178205, 164043, 177296, 166060, 166061, 168222, 168223, 168224,
    168729, 174220, 174221, 174222, 175391, 175392, 175393, 177297, 178204, 179612, 179613, 179614,
    169891, 172606, 181345, 179635, 162044, 162045, 162046, 164042, 165175, 181342, 181375, 183032,
    185741, 185742, 168731, 161754, 161757, 162016, 162019, 162020, 155306, 162023, 162030, 162035,
    162037, 162042, 162043, 162051, 162054, 162055, 162059, 162060, 162061, 162064, 162076, 162080,
    162089, 162095, 162096, 162097, 162103, 162107, 162110, 162114, 162116, 162117, 162122, 162312,
    162393, 163044, 163080, 164044, 171555, 181343, 181344, 181343, 181344, 200479, 216321, 216323,
    216324, 216322,
];

struct MicrosoftSqlServer;

impl PostProcess for MicrosoftSqlServer {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "microsoft_sql_server",
            order: 1044,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99928,
            "Missing the latest Microsoft SQL Server",
            "Update to the latest Microsoft SQL Server",
            "Microsoft SQL Server Patch Rollup",
            PLUGIN_IDS_MICROSOFT_SQL_SERVER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MicrosoftSqlServer }
}

const PLUGIN_IDS_MICROSOFT_SQL_SERVER: &[i32] = &[
    193160, 193161, 205300, 11214, 11322, 11804, 33444, 34311, 35632, 35635, 62465, 77162, 84738,
    94637, 145033, 126631, 133719, 111786, 171604, 180007, 175440, 178851, 183036, 175450, 175441,
    178852, 182968, 207065, 207067, 211472, 182956,
];

struct MicrosoftVisualStudio;

impl PostProcess for MicrosoftVisualStudio {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "microsoft_visual_studio",
            order: 1045,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99940,
            "Missing the latest Microsoft Visual Studio",
            "Update to the latest Microsoft Visual Studio",
            "Microsoft Visual Studio Patch Rollup",
            PLUGIN_IDS_MICROSOFT_VISUAL_STUDIO,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MicrosoftVisualStudio }
}

const PLUGIN_IDS_MICROSOFT_VISUAL_STUDIO: &[i32] = &[121065];

struct MicrosoftWindows;

impl PostProcess for MicrosoftWindows {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "microsoft_windows",
            order: 1046,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99983,
            "Missing the latest Windows Updates Patches",
            "Update to the latest Windows Updates",
            "Microsoft Windows Patch Rollup",
            PLUGIN_IDS_MICROSOFT_WINDOWS,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MicrosoftWindows }
}

const PLUGIN_IDS_MICROSOFT_WINDOWS: &[i32] = &[
    11110, 11808, 11835, 11890, 12054, 12209, 13852, 14724, 18026, 18482, 18502, 18681, 19402,
    19403, 19405, 19407, 19408, 19998, 19999, 20001, 20003, 20004, 20389, 20390, 20907, 20908,
    21078, 21193, 21211, 21655, 21686, 21687, 21689, 21690, 21692, 21694, 22028, 22030, 22034,
    22183, 22188, 22189, 22190, 22192, 22194, 22333, 22334, 22529, 22530, 22532, 22533, 22534,
    22535, 22536, 22537, 22538, 23643, 23644, 23645, 23833, 23837, 23838, 23998, 23999, 24330,
    24332, 24335, 24337, 24338, 24339, 24340, 24911, 25025, 25162, 25163, 25164, 25166, 25167,
    25484, 25486, 25488, 25687, 25688, 25691, 25880, 25882, 25883, 25884, 25886, 26962, 26963,
    27525, 28183, 28185, 29308, 29311, 29312, 29313, 29893, 29894, 31039, 31040, 31041, 31042,
    31044, 31793, 31794, 31795, 31797, 31798, 32310, 32311, 32312, 33107, 33132, 33133, 33134,
    33135, 33137, 33441, 33870, 33871, 33872, 33873, 33874, 33875, 33877, 33878, 33879, 33880,
    33881, 34120, 34121, 34123, 34402, 34403, 34406, 34408, 34409, 34411, 34414, 34476, 34477,
    34743, 34744, 35069, 35070, 35071, 35072, 35073, 35075, 35221, 35361, 35630, 35634, 35822,
    35823, 36147, 36148, 36149, 36150, 36151, 36152, 36153, 38742, 39341, 39342, 39343, 39344,
    39346, 39347, 39348, 39349, 39350, 39622, 39783, 39791, 39792, 39793, 40407, 40435, 40556,
    40557, 40559, 40560, 40561, 40562, 40564, 40565, 40888, 40889, 40890, 40891, 42107, 42108,
    42110, 42112, 42113, 42114, 42115, 42116, 42117, 42118, 42439, 42441, 42442, 43061, 43063,
    43064, 43065, 43089, 43865, 44045, 44110, 44414, 44415, 44416, 44417, 44418, 44421, 44422,
    44423, 44425, 45020, 45021, 45378, 45506, 45507, 45508, 45509, 45510, 45513, 45514, 45516,
    45517, 46312, 46313, 46839, 46840, 46841, 46842, 46843, 46844, 46845, 46847, 46848, 47045,
    47556, 47710, 47711, 47712, 47713, 47750, 48216, 48284, 48285, 48286, 48287, 48288, 48289,
    48290, 48291, 48292, 48293, 48294, 48295, 48296, 48297, 48405, 48761, 48762, 49219, 49220,
    49221, 49222, 49223, 49224, 49225, 49227, 49274, 49695, 49948, 49950, 49951, 49953, 49954,
    49955, 49956, 49957, 49958, 49959, 49960, 49961, 49962, 50528, 50529, 51162, 51163, 51164,
    51166, 51167, 51168, 51169, 51170, 51171, 51172, 51175, 51177, 51455, 51587, 51903, 51904,
    51906, 51907, 51909, 51910, 51911, 51912, 51913, 51914, 51956, 52456, 52583, 52585, 53375,
    53376, 53377, 53378, 53379, 53381, 53382, 53383, 53384, 53385, 53386, 53387, 53388, 53389,
    53390, 53391, 53503, 53514, 53830, 53859, 55116, 55117, 55118, 55119, 55121, 55122, 55123,
    55124, 55125, 55126, 55128, 55129, 55130, 55132, 55569, 55570, 55572, 55787, 55792, 55793,
    55794, 55795, 55796, 55797, 55798, 55799, 55802, 56174, 56175, 56177, 56449, 56450, 56451,
    56452, 56454, 56455, 56736, 56737, 56738, 56824, 57273, 57275, 57276, 57277, 57278, 57279,
    57280, 57282, 57283, 57284, 57285, 57414, 57469, 57470, 57471, 57472, 57473, 57474, 57942,
    57943, 57944, 57946, 57947, 57948, 57949, 57950, 58330, 58331, 58332, 58333, 58335, 58655,
    58656, 58657, 58659, 59037, 59038, 59039, 59040, 59041, 59042, 59043, 59044, 59454, 59455,
    59456, 59459, 59460, 59906, 59907, 59908, 59909, 59910, 59911, 59912, 59915, 61527, 61528,
    61529, 61530, 61531, 61532, 61534, 61535, 62045, 62223, 62459, 62461, 62463, 62464, 62466,
    62903, 62904, 62905, 62906, 62907, 62908, 62940, 63224, 63225, 63226, 63228, 63229, 63230,
    63419, 63420, 63422, 63423, 63424, 63425, 63522, 64570, 64571, 64572, 64576, 64577, 64578,
    64579, 64580, 64581, 65210, 65212, 65214, 65215, 65875, 65876, 65878, 65879, 65880, 65883,
    66412, 66413, 66415, 66417, 66418, 66421, 66422, 66423, 66425, 66863, 66864, 66865, 66866,
    67209, 67210, 67211, 67212, 67213, 67214, 67215, 69324, 69325, 69327, 69328, 69330, 69334,
    69828, 69829, 69830, 69831, 69832, 69833, 69834, 69835, 69836, 69838, 70332, 70333, 70334,
    70335, 70337, 70338, 70339, 70395, 70846, 70847, 70848, 70849, 70851, 70852, 70853, 70854,
    71311, 71312, 71313, 71314, 71316, 71317, 71321, 71323, 71941, 71942, 71943, 72428, 72430,
    72432, 72433, 72434, 72930, 72931, 72932, 72934, 72935, 73413, 73415, 73416, 73417, 73805,
    73982, 73983, 73984, 73985, 73986, 73987, 73988, 73990, 73992, 74422, 74423, 74425, 74426,
    74427, 74428, 76123, 76406, 76407, 76408, 76409, 76410, 77160, 77163, 77164, 77165, 77166,
    77167, 77169, 77572, 77573, 77574, 78431, 78432, 78433, 78435, 78437, 78438, 78439, 78446,
    78447, 79125, 79126, 79127, 79128, 79129, 79130, 79131, 79132, 79134, 79137, 79138, 79311,
    79828, 79830, 79831, 79832, 79833, 79834, 80490, 80491, 80492, 80493, 80494, 80496, 80497,
    81262, 81263, 81264, 81265, 81266, 81267, 81268, 81269, 81731, 81733, 81734, 81735, 81736,
    81737, 81738, 81739, 81741, 81742, 81743, 81744, 81745, 81757, 82075, 82769, 82770, 82771,
    82772, 82774, 82775, 82777, 82793, 82828, 83354, 83355, 83356, 83358, 83360, 83361, 83362,
    83363, 83364, 83370, 83416, 83440, 84053, 84054, 84055, 84056, 84057, 84059, 84734, 84735,
    84736, 84739, 84741, 84742, 84743, 84744, 84745, 84746, 84747, 84748, 84761, 84763, 84882,
    85321, 85322, 85323, 85329, 85330, 85332, 85333, 85334, 85335, 85348, 85350, 85540, 85844,
    85845, 85846, 85847, 85876, 85877, 85879, 85884, 86065, 86149, 86366, 86367, 86371, 86373,
    86374, 86469, 86819, 86820, 86821, 86822, 86823, 86824, 86825, 86826, 86827, 86828, 86856,
    87249, 87252, 87253, 87254, 87256, 87257, 87258, 87259, 87260, 87261, 87262, 87263, 87264,
    87313, 87671, 87875, 87877, 87878, 87880, 87881, 87882, 87890, 87892, 87893, 88642, 88643,
    88644, 88645, 88646, 88647, 88648, 88649, 88650, 88651, 88653, 88654, 89746, 89747, 89748,
    89749, 89750, 89751, 89752, 89753, 89754, 89755, 89756, 89757, 89779, 89835, 90431, 90432,
    90433, 90434, 90436, 90437, 90438, 90439, 90440, 90441, 90442, 90443, 90510, 91001, 91002,
    91004, 91005, 91006, 91007, 91009, 91010, 91011, 91012, 91013, 91014, 91015, 91596, 91600,
    91601, 91602, 91603, 91609, 92018, 92021, 92022, 92821, 92823, 92843, 91599, 93466, 93470,
    93473, 93651, 93464, 93468, 92015, 92819, 91604, 90435, 91607, 92023, 92025, 92822, 92824,
    93469, 93481, 91605, 91672, 92024, 93475, 93471, 84762, 85331, 81732, 82823, 83369, 84052,
    84367, 84645, 84809, 94012, 94017, 94011, 94014, 94016, 49952, 94634, 55883, 72836, 95764,
    95765, 95766, 95768, 95811, 95813, 96393, 97833, 97737, 97743, 100051, 100057, 94631, 94633,
    94635, 94636, 94638, 94639, 94641, 94643, 97729, 97731, 97732, 97733, 97738, 97794, 99312,
    97740, 99314, 100103, 100058, 97833, 100761, 101367, 100767, 101371, 102267, 94632, 102035,
    99304, 99365, 100551, 102270, 97734, 97736, 97741, 97742, 55286, 58435, 79638, 99286, 100059,
    100760, 101366, 97730, 94340, 94630, 94642, 95767, 95771, 95809, 96392, 97325, 97735, 99290,
    100062, 100766, 101370, 102266, 102683, 100054, 100762, 100764, 101365, 101375, 102264, 97745,
    102268, 101027, 95772, 96390, 79638, 35362, 100763, 103123, 103138, 103131, 103127, 103746,
    103220, 103750, 103924, 100768, 100782, 103122, 103133, 103136, 103456, 103745, 103752, 103784,
    103876, 103137, 100464, 40887, 100791, 104892, 105552, 105546, 105731, 104893, 99523, 105553,
    106800, 106804, 108291, 104554, 104890, 104891, 104894, 104895, 104896, 105185, 105188, 105109,
    104553, 105184, 106802, 106804, 108290, 108295, 108757, 108813, 108966, 108971, 109652, 109604,
    109613, 109605, 110487, 108964, 109608, 108284, 110485, 104551, 105550, 106795, 104889, 110490,
    110494, 105183, 103128, 103134, 103751, 103754, 104558, 104559, 110990, 111689, 104556, 104562,
    52544, 109684, 111755, 110994, 108969, 108972, 109612, 109614, 109617, 110495, 110499, 110500,
    104557, 105189, 105192, 105694, 105699, 105700, 105728, 106805, 106807, 108301, 110982, 110991,
    111694, 111696, 111787, 111685, 111690, 103135, 103569, 103749, 104549, 111695, 110486, 111698,
    110491, 110980, 111008, 108967, 108970, 108973, 109606, 109615, 105695, 105697, 106796, 106817,
    108289, 108292, 108297, 105548, 105180, 100760, 101366, 111685, 103132, 117421, 117423, 117418,
    117426, 117411, 111691, 110984, 111687, 117417, 111688, 117412, 103748, 104555, 105186, 105554,
    106799, 108968, 109610, 110488, 110987, 117424, 117415, 117422, 118001, 118007, 118009, 118010,
    118014, 118015, 118016, 108962, 101374, 109609, 110414, 110988, 111700, 117998, 119589, 119771,
    118915, 119612, 121020, 121024, 121028, 117431, 121021, 121027, 121035, 119609, 119582, 122234,
    118913, 121017, 122118, 122782, 118922, 119594, 119774, 121023, 122131, 122789, 122317, 111692,
    119463, 119587, 119772, 119095, 100785, 118920, 118921, 118923, 118928, 118930, 119592, 119595,
    119598, 119599, 121015, 121016, 122121, 122123, 122132, 122779, 122783, 104045, 110989, 117458,
    118005, 122974, 122975, 119583, 110484, 110981, 118002, 118918, 121014, 122120, 122784, 123942,
    123945, 123949, 123952, 118012, 121025, 123940, 123950, 123951, 125313, 119586, 122819, 124117,
    125073, 125822, 125064, 125820, 117999, 125818, 110983, 122119, 122786, 123939, 125828, 125066,
    125069, 125824, 125061, 109607, 125063, 125817, 125816, 125058, 112116, 127843, 127846, 127850,
    126600, 126570, 126571, 126582, 108965, 122785, 123943, 126577, 125074, 86818, 86830, 88652,
    91016, 91045, 93474, 63643, 99289, 127852, 111693, 80495, 82778, 85848, 94013, 95770, 128647,
    127910, 128637, 128640, 130909, 130912, 130906, 132862, 132863, 127845, 129166, 129718, 129728,
    130905, 131934, 131936, 132868, 126569, 128639, 133619, 130907, 131930, 131933, 133610, 133615,
    132866, 132999, 129724, 117413, 118916, 119584, 132858, 134369, 122615, 125060, 132864, 117997,
    119769, 121012, 122126, 129719, 131927, 133611, 123944, 126573, 127842, 128636, 129720, 130904,
    131929, 137265, 128646, 134372, 139498, 138467, 136512, 137266, 134864, 134865, 135472, 136507,
    137260, 138460, 135466, 136503, 137259, 138455, 138463, 136509, 137255, 137262, 138457, 134863,
    134866, 135470, 136510, 137263, 128642, 129722, 134374, 134377, 135471, 138461, 133618, 135475,
    139491, 140422, 134942, 138600, 134204, 134368, 132859, 137256, 138453, 139484, 140414, 135463,
    136501, 133608, 129717, 130901, 131932, 142690, 142683, 142680, 141431, 141427, 141493, 142691,
    147231, 148465, 148466, 147222, 148482, 147229, 148477, 143572, 144877, 146342, 146329, 144882,
    148693, 150370, 150369, 142686, 150354, 150368, 139489, 140424, 141416, 143560, 144888, 146341,
    148461, 149392, 150721, 149386, 149383, 146326, 147220, 149398, 136946, 151474, 151592, 152434,
    150367, 149394, 151477, 151598, 152433, 151597, 152587, 151476, 151611, 152436, 153379, 154035,
    144952, 154956, 154986, 154993, 154990, 154996, 152435, 153373, 154026, 151588, 137258, 138458,
    139488, 140417, 141434, 143569, 149390, 153377, 154034, 154040, 151473, 154984, 140428, 151488,
    156063, 139490, 140418, 141422, 142682, 143571, 144880, 146339, 147224, 148468, 149391, 153382,
    158708, 161921, 162196, 163052, 147223, 156619, 156621, 159675, 159677, 162197, 166025, 166039,
    143561, 144887, 146337, 148473, 149382, 150374, 156071, 157432, 157436, 158704, 158712, 160928,
    160934, 163046, 163940, 163946, 164996, 164997, 166034, 153375, 166030, 159682, 167112, 167115,
    167109, 167111, 159672, 163952, 169779, 169781, 169788, 156069, 156627, 157427, 158718, 160937,
    162191, 163050, 168693, 147228, 152432, 153374, 154032, 171441, 171448, 177247, 177246, 178156,
    178159, 178150, 176328, 182865, 182854, 144813, 175373, 200349, 200351, 206973, 161691, 210860,
    210850, 169783, 152102,
];

struct MicrosoftWindows10;

impl PostProcess for MicrosoftWindows10 {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "microsoft_windows_10",
            order: 1047,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99922,
            "Missing the latest Microsoft Windows 10",
            "Update to the latest Microsoft Windows 10",
            "Microsoft Windows 10 Patch Rollup",
            PLUGIN_IDS_MICROSOFT_WINDOWS_10,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MicrosoftWindows10 }
}

const PLUGIN_IDS_MICROSOFT_WINDOWS_10: &[i32] = &[
    170963, 208292, 205452, 206894, 187795, 190468, 191944, 193090, 197014, 202037, 200343, 206898,
    208285, 172532, 172533, 174108, 174120, 175339, 175347, 178152, 179487, 179498, 182862, 185576,
    185579, 202028, 202043, 205447, 206902, 208298, 205461, 168694, 181303, 181312, 186789, 186791,
    187800, 187803, 190482, 190487, 191934, 191938, 212239, 214115, 214123, 216134, 193091, 193097,
    197006, 197009, 212232, 216131,
];

struct MicrosoftWindowsServer;

impl PostProcess for MicrosoftWindowsServer {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "microsoft_windows_server",
            order: 1048,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99926,
            "Missing the latest Microsoft Windows Server",
            "Update to the latest Microsoft Windows Server",
            "Microsoft Windows Server Patch Rollup",
            PLUGIN_IDS_MICROSOFT_WINDOWS_SERVER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MicrosoftWindowsServer }
}

const PLUGIN_IDS_MICROSOFT_WINDOWS_SERVER: &[i32] = &[
    162205, 163045, 166032, 167107, 200336, 202039, 205456, 206897, 208295, 168690, 169776, 181305,
    186777, 187790, 190481, 191947, 193095, 197015, 159681, 160929, 163953, 165000, 171444, 172518,
    174113, 175341, 177235, 178155, 179492, 182851, 185588, 191942, 193101, 197010, 187901, 190478,
    186782, 190490, 171440, 172517, 174103, 175344, 177241, 178168, 179489, 185577, 187799, 187805,
    179501, 182864, 200338, 168687, 171453, 172535, 174118, 163947, 165005, 175349, 186781, 182857,
    181299, 156073, 156624, 157431, 158702, 163042, 160931, 162202, 169789, 177237, 168681, 165002,
    166024, 167103, 202034, 205453, 206896, 208305, 210861, 212233, 214135, 216139, 232622,
];

struct MongoDb;

impl PostProcess for MongoDb {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "mongo_db",
            order: 1049,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99943,
            "Missing the latest MongoDB",
            "Update to the latest MongoDB",
            "MongoDB Patch Rollup",
            PLUGIN_IDS_MONGO_DB,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MongoDb }
}

const PLUGIN_IDS_MONGO_DB: &[i32] = &[122243];

struct MozzilaThunderbird;

impl PostProcess for MozzilaThunderbird {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "mozzila_thunderbird",
            order: 1050,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99949,
            "Missing the latest Mozzila Thunderbird Patches",
            "Update to the latest Mozzila Thunderbird",
            "Mozzila Thunderbird Patch Rollup",
            PLUGIN_IDS_MOZZILA_THUNDERBIRD,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &MozzilaThunderbird }
}

const PLUGIN_IDS_MOZZILA_THUNDERBIRD: &[i32] = &[105507, 108519, 109946, 105044, 111044];

struct Mysql;

impl PostProcess for Mysql {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "mysql",
            order: 1051,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99932,
            "Missing the latest MySQL",
            "Update to the latest MySQL",
            "MySQL Patch Rollup",
            PLUGIN_IDS_MYSQL,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Mysql }
}

const PLUGIN_IDS_MYSQL: &[i32] = &[
    132957, 141797, 154259, 148936, 151969, 145247, 138561, 138570,
];

struct NextgenMirthConnect;

impl PostProcess for NextgenMirthConnect {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "nextgen_mirth_connect",
            order: 1052,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99929,
            "Missing the latest NextGen Mirth Connect",
            "Update to the latest NextGen Mirth Connect",
            "NextGen Mirth Connect Patch Rollup",
            PLUGIN_IDS_NEXTGEN_MIRTH_CONNECT,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &NextgenMirthConnect }
}

const PLUGIN_IDS_NEXTGEN_MIRTH_CONNECT: &[i32] = &[183968, 183969];

struct Nginx;

impl PostProcess for Nginx {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "nginx",
            order: 1053,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99914,
            "Missing the latest Nginx",
            "Update to the latest Nginx",
            "Nginx Patch Rollup",
            PLUGIN_IDS_NGINX,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Nginx }
}

const PLUGIN_IDS_NGINX: &[i32] = &[134220];

struct NotepadPlusPlus;

impl PostProcess for NotepadPlusPlus {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "notepad_plus_plus",
            order: 1054,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99927,
            "Missing the latest Notepad++",
            "Update to the latest Notepad++",
            "Notepad++ Patch Rollup",
            PLUGIN_IDS_NOTEPAD_PLUS_PLUS,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &NotepadPlusPlus }
}

const PLUGIN_IDS_NOTEPAD_PLUS_PLUS: &[i32] = &[208192, 181867, 205291];

struct Openoffice;

impl PostProcess for Openoffice {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "openoffice",
            order: 1055,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99963,
            "Missing the latest OpenOffice Patches",
            "Update to the latest OpenOffice",
            "OpenOffice Patch Rollup",
            PLUGIN_IDS_OPENOFFICE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Openoffice }
}

const PLUGIN_IDS_OPENOFFICE: &[i32] = &[
    77408, 86904, 94199, 61731, 69185, 51773, 58727, 59191, 104351, 40826, 44597, 46814,
];

struct Openssh;

impl PostProcess for Openssh {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "openssh",
            order: 1056,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99995,
            "Missing the latest OpenSSH Patches",
            "Update to the latest OpenSSH",
            "OpenSSH Patch Rollup",
            PLUGIN_IDS_OPENSSH,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Openssh }
}

const PLUGIN_IDS_OPENSSH: &[i32] = &[
    11837, 17702, 44077, 44078, 44065, 31737, 44074, 44076, 44079, 19592, 44075, 53841, 44080,
    44077, 44078, 85382, 86122, 10883, 11031, 10771, 10823, 10954, 11712, 44072, 10802, 90022,
    93194, 96151, 201194, 106608, 99359, 103781, 159490, 159491, 187201, 84638, 90023, 90924,
    85690, 234554,
];

struct Openssl;

impl PostProcess for Openssl {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "openssl",
            order: 1057,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99984,
            "Missing the latest OpenSSL Patches",
            "Update to the latest OpenSSL",
            "OpenSSL Patch Rollup",
            PLUGIN_IDS_OPENSSL,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Openssl }
}

const PLUGIN_IDS_OPENSSL: &[i32] = &[
    11267, 12110, 74363, 77086, 74326, 73412, 77200, 17757, 73404, 74364, 77088, 17755, 17756,
    17758, 17759, 17761, 17762, 17763, 17765, 57459, 58799, 17760, 56996, 58564, 59076, 64532,
    71857, 78554, 80568, 82032, 84153, 51892, 17766, 17767, 90888, 93814, 89081, 84636, 87221,
    88529, 90890, 93112, 89082, 96873, 93815, 78552, 80566, 82030, 84151, 87219, 87222, 88530,
    90891, 109945, 112119, 104408,
];

struct OracleDatabase;

impl PostProcess for OracleDatabase {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "oracle_database",
            order: 1058,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99993,
            "Missing the latest Oracle Database Patches",
            "Update to the latest Oracle Database",
            "Oracle Database Patch Rollup",
            PLUGIN_IDS_ORACLE_DATABASE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &OracleDatabase }
}

const PLUGIN_IDS_ORACLE_DATABASE: &[i32] = &[
    45625, 56051, 56052, 56053, 56056, 56066, 50652, 47718, 45626, 51573, 53897, 56054, 56055,
    56057, 56058, 56060, 56064, 56065, 56059, 56061, 56062, 56063, 56653, 57589, 55632, 11227,
    10848, 10851, 11223, 11224, 11226, 10852, 55786, 84822, 82903, 80906, 78540, 72982,
];

struct Php;

impl PostProcess for Php {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "php",
            order: 1059,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99988,
            "Missing the latest PHP Patches",
            "Update to the latest PHP",
            "PHP Patch Rollup",
            PLUGIN_IDS_PHP,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Php }
}

const PLUGIN_IDS_PHP: &[i32] = &[
    76281, 66843, 67260, 69401, 72881, 46803, 66585, 71427, 71927, 73338, 73862, 74291, 76791,
    11850, 15973, 17710, 17796, 18033, 20111, 22268, 24906, 29833, 33849, 35067, 41014, 57537,
    58966, 66842, 58988, 67259, 77285, 35750, 39480, 43351, 44921, 64992, 66584, 71426, 77402,
    78545, 79246, 80330, 81080, 81510, 82025, 83033, 83517, 84362, 84671, 32123, 35043, 48244,
    28181, 51139, 51439, 73289, 60085, 48245, 51140, 52717, 55925, 59056, 59529, 88679, 88694,
    90008, 90361, 91442, 91898, 92555, 93656, 94106, 94955, 95874, 101525, 90921, 93077, 96799,
    104631, 107216, 119764, 105771, 109576, 111230, 117497, 84673, 84364, 85300, 85887, 121602,
    86301, 122591, 130276, 123829, 128531, 129557, 125681, 126637, 127132, 135918, 136741, 138593,
    140532, 122750, 123755, 124764, 142591, 25368, 25971, 154349, 155589, 158133, 161971, 166901,
    165545,
];

struct PostgresSql;

impl PostProcess for PostgresSql {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "postgres_sql",
            order: 1060,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99933,
            "Missing the latest Postgres SQL",
            "Update to the latest Postgres SQL",
            "Postgres SQL Patch Rollup",
            PLUGIN_IDS_POSTGRES_SQL,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &PostgresSql }
}

const PLUGIN_IDS_POSTGRES_SQL: &[i32] = &[127905, 94610, 97435, 125264, 110288, 144060];

struct Putty;

impl PostProcess for Putty {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "putty",
            order: 1061,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99938,
            "Missing the latest PuTTY",
            "Update to the latest PuTTY",
            "PuTTY Patch Rollup",
            PLUGIN_IDS_PUTTY,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Putty }
}

const PLUGIN_IDS_PUTTY: &[i32] = &[123418, 105154, 193433];

struct RealPlayer;

impl PostProcess for RealPlayer {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "real_player",
            order: 1062,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99957,
            "Missing the latest RealPlayer Patches",
            "Update to the latest RealPlayer",
            "RealPlayer Patch Rollup",
            PLUGIN_IDS_REAL_PLAYER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &RealPlayer }
}

const PLUGIN_IDS_REAL_PLAYER: &[i32] = &[57863, 59173, 62065, 63289, 65630, 69472, 71772, 76458];

struct Samba;

impl PostProcess for Samba {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "samba",
            order: 1063,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99944,
            "Missing the latest Samba",
            "Update to the latest Samba",
            "Samba Patch Rollup",
            PLUGIN_IDS_SAMBA,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Samba }
}

const PLUGIN_IDS_SAMBA: &[i32] = &[125388, 157360];

struct Servu;

impl PostProcess for Servu {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "servu",
            order: 1064,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99996,
            "Missing the latest Serv-U Patches",
            "Update to the latest Serv-U",
            "Serv-U Patch Rollup",
            PLUGIN_IDS_SERVU,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Servu }
}

const PLUGIN_IDS_SERVU: &[i32] = &[
    36035, 41980, 48435, 69060, 71863, 72658, 76369, 151646, 156886, 169899, 177024, 193517, 207863,
];

struct SigplusPro;

impl PostProcess for SigplusPro {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "sigplus_pro",
            order: 1065,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99977,
            "Missing the latest SigPlus Pro Patches",
            "Update to the latest SigPlus Pro",
            "SigPlus Pro Patch Rollups",
            PLUGIN_IDS_SIGPLUS_PRO,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &SigplusPro }
}

const PLUGIN_IDS_SIGPLUS_PRO: &[i32] = &[51895, 51894];

struct Skype;

impl PostProcess for Skype {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "skype",
            order: 1066,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99955,
            "Missing the latest Skype Patches",
            "Update to the latest Skype",
            "Skype Patch Rollup",
            PLUGIN_IDS_SKYPE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Skype }
}

const PLUGIN_IDS_SKYPE: &[i32] = &[66695, 101084];

struct SolarwindsDameware;

impl PostProcess for SolarwindsDameware {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "solarwinds_dameware",
            order: 1067,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99936,
            "Missing the latest SolarWinds DameWare",
            "Update to the latest SolarWinds DameWare",
            "SolarWinds DameWare Patch Rollup",
            PLUGIN_IDS_SOLARWINDS_DAMEWARE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &SolarwindsDameware }
}

const PLUGIN_IDS_SOLARWINDS_DAMEWARE: &[i32] = &[124062, 130458, 126263];

struct SybaseAsaClientConnectionBroadcast;

impl PostProcess for SybaseAsaClientConnectionBroadcast {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "sybase_asa_client_connection_broadcast",
            order: 1068,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99915,
            "Missing the latest Sybase ASA Client Connection Broadcast",
            "Update to the latest Sybase ASA Client Connection Broadcast",
            "Sybase ASA Client Connection Broadcast Patch Rollup",
            PLUGIN_IDS_SYBASE_ASA_CLIENT_CONNECTION_BROADCAST,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &SybaseAsaClientConnectionBroadcast }
}

const PLUGIN_IDS_SYBASE_ASA_CLIENT_CONNECTION_BROADCAST: &[i32] = &[25926];

struct SymantecEndpoint;

impl PostProcess for SymantecEndpoint {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "symantec_endpoint",
            order: 1069,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99953,
            "Missing the latest Symantec Endpoint Patches",
            "Update to the latest Symantec Endpoint",
            "Symantec Endpoint Patch Rollup",
            PLUGIN_IDS_SYMANTEC_ENDPOINT,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &SymantecEndpoint }
}

const PLUGIN_IDS_SYMANTEC_ENDPOINT: &[i32] = &[
    91895, 71993, 90199, 59366, 71994, 72542, 85256, 104459, 131233,
];

struct SymantecPcanywhere;

impl PostProcess for SymantecPcanywhere {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "symantec_pcanywhere",
            order: 1070,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99971,
            "Missing the latest Symantec pcAnywhere Patches",
            "Update to the latest Symantec pcAnywhere",
            "Symantec pcAnywhere Patch Rollup",
            PLUGIN_IDS_SYMANTEC_PCANYWHERE,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &SymantecPcanywhere }
}

const PLUGIN_IDS_SYMANTEC_PCANYWHERE: &[i32] = &[20743, 57796, 58119, 35976, 58204];

struct TenableNessus;

impl PostProcess for TenableNessus {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "tenable_nessus",
            order: 1071,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99945,
            "Missing the latest Tenable Nessus",
            "Update to the latest Tenable Nessus",
            "Tenable Nessus Patch Rollup",
            PLUGIN_IDS_TENABLE_NESSUS,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &TenableNessus }
}

const PLUGIN_IDS_TENABLE_NESSUS: &[i32] = &[123462, 121620];

struct Timbuktu;

impl PostProcess for Timbuktu {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "timbuktu",
            order: 1072,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99964,
            "Missing the latest Timbuktu Pro Patches",
            "Update to the latest Timbuktu Pro",
            "Timbuktu Pro Patch Rollup",
            PLUGIN_IDS_TIMBUKTU,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Timbuktu }
}

const PLUGIN_IDS_TIMBUKTU: &[i32] = &[25954, 39563];

struct Ubuntu;

impl PostProcess for Ubuntu {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "ubuntu",
            order: 1073,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99921,
            "Missing the latest Ubuntu Linux",
            "Update to the latest Ubuntu Linux",
            "Ubuntu Linux Patch Rollup",
            PLUGIN_IDS_UBUNTU,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Ubuntu }
}

const PLUGIN_IDS_UBUNTU: &[i32] = &[
    214997, 216055, 214671, 214738, 214777, 214790, 172614, 183778, 215062, 183116, 183123, 214506,
    214894, 198152, 206422, 182982, 213545, 214505, 214820, 215238,
];

struct VeeamBackupAndReplication;

impl PostProcess for VeeamBackupAndReplication {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "veeam_backup_and_replication",
            order: 1074,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99917,
            "Missing the latest Veeam Backup and Replication",
            "Update to the latest Veeam Backup and Replication",
            "Veeam Backup and Replication Patch Rollup",
            PLUGIN_IDS_VEEAM_BACKUP_AND_REPLICATION,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &VeeamBackupAndReplication }
}

const PLUGIN_IDS_VEEAM_BACKUP_AND_REPLICATION: &[i32] = &[168945, 173398];

struct Vlc;

impl PostProcess for Vlc {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "vlc",
            order: 1075,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99970,
            "Missing the latest VLC Patches",
            "Update to the latest VLC",
            "VLC Patch Rollup",
            PLUGIN_IDS_VLC,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Vlc }
}

const PLUGIN_IDS_VLC: &[i32] = &[
    58416, 60049, 63381, 66216, 72279, 69015, 70560, 78626, 55608, 63137, 100592, 105294, 136422,
    126246, 128080,
];

struct VmwareEsxi;

impl PostProcess for VmwareEsxi {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "vmware_esxi",
            order: 1076,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99981,
            "Missing the latest VMware ESXi Patches",
            "Update to the latest VMware ESXi",
            "VMware ESXi Patch Rollup",
            PLUGIN_IDS_VMWARE_ESXI,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &VmwareEsxi }
}

const PLUGIN_IDS_VMWARE_ESXI: &[i32] = &[
    70879, 70880, 70882, 70883, 70884, 70885, 70888, 59447, 70877, 70878, 70881, 70886, 70887,
    71773, 72037, 76203, 76368, 73917, 81085, 71774, 74470, 78108, 79862, 80037, 81084, 83781,
    86947, 86946, 86945, 87676, 81083, 87940, 89035, 89036, 89037, 89038, 87673, 87674, 87677,
    87678, 88906, 92949, 87943, 89106, 89105, 89108, 89678, 89680, 99129, 99130, 87679, 87942,
    103375, 105486, 87941, 87681, 105614, 111759, 118466, 102698, 118885, 123518, 134878, 143221,
    138475, 140039, 158494, 99131, 103376, 168828, 176249, 146827, 151665, 192466, 191711,
];

struct VmwarePlayer;

impl PostProcess for VmwarePlayer {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "vmware_player",
            order: 1077,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99976,
            "Missing the latest VMware Player Patches",
            "Update to the latest VMware Player",
            "VMware Player Patch Rollup",
            PLUGIN_IDS_VMWARE_PLAYER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &VmwarePlayer }
}

const PLUGIN_IDS_VMWARE_PLAYER: &[i32] = &[71231, 76454, 73672, 74265, 84219, 84805, 81185];

struct VmwareVcenter;

impl PostProcess for VmwareVcenter {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "vmware_vcenter",
            order: 1078,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99979,
            "Missing the latest VMware vCenter Patches",
            "Update to the latest VMware vCenter",
            "VMware vCenter Patch Rollup",
            PLUGIN_IDS_VMWARE_VCENTER,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &VmwareVcenter }
}

const PLUGIN_IDS_VMWARE_VCENTER: &[i32] = &[
    79865, 66274, 66806, 70612, 77728, 65209, 65223, 76457, 83186, 81146, 79147, 86255, 66812,
    87763, 90710, 91322, 87592, 92870, 91713, 76947, 99475, 104654, 86124, 95468, 105784, 111760,
    79864, 129503, 149902, 150163, 146825, 146826, 153544, 153889, 135411, 140040, 150982, 155790,
    166101, 163100, 168746, 183957, 183958,
];

struct VmwareVsphereClient;

impl PostProcess for VmwareVsphereClient {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "vmware_vsphere_client",
            order: 1079,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99967,
            "Missing the latest VMware vSphere Client Patches",
            "Update to the latest VMware vSphere Client",
            "VMware vSphere Client Patch Rollup",
            PLUGIN_IDS_VMWARE_VSPHERE_CLIENT,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &VmwareVsphereClient }
}

const PLUGIN_IDS_VMWARE_VSPHERE_CLIENT: &[i32] = &[64559, 73595, 51057, 76355, 87675, 95657];

struct WindRiverVxworks;

impl PostProcess for WindRiverVxworks {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "wind_river_vxworks",
            order: 1080,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99931,
            "Missing the latest Wind River VXWorks",
            "Update to the latest Wind River VXWorks",
            "Wind River VXWorks Patch Rollup",
            PLUGIN_IDS_WIND_RIVER_VXWORKS,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &WindRiverVxworks }
}

const PLUGIN_IDS_WIND_RIVER_VXWORKS: &[i32] = &[152701, 154458];

struct Winscp;

impl PostProcess for Winscp {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "winscp",
            order: 1081,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99978,
            "Missing the latest WinSCP Patches",
            "Update to the latest WinSCP",
            "WinSCP Patch Rollups",
            PLUGIN_IDS_WINSCP,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Winscp }
}

const PLUGIN_IDS_WINSCP: &[i32] = &[73613, 76167, 78078, 72388, 72389, 177397, 205312];

struct Wireshark;

impl PostProcess for Wireshark {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "wireshark",
            order: 1082,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99992,
            "Missing the latest Wireshark Patches",
            "Update to the latest Wireshark",
            "Wireshark Patch Rollups",
            PLUGIN_IDS_WIRESHARK,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &Wireshark }
}

const PLUGIN_IDS_WIRESHARK: &[i32] = &[
    61572, 64361, 65253, 66543, 65254, 66544, 72941, 66895, 69104, 69880, 70763, 71520, 56164,
    56690, 58518, 59240, 60117, 62477, 63095, 66894, 57539, 53473, 57538, 61571, 54942, 55510,
    56163, 56689, 58517, 59239, 60116, 51458, 52502, 83488, 36127, 40335, 43350, 44338, 46864,
    48213, 48943, 89103, 90786, 90787, 92817, 99437, 97574, 89104, 91821, 100671, 91820, 92816,
    50678, 107093, 108885, 110269, 111387, 117339, 101898, 102920, 103985, 105007, 106142, 102919,
    103984, 118206, 119419, 121107, 124164, 125365, 126923, 129061, 119420, 121108, 124165, 125367,
    126921, 134112, 142421, 139573, 140757, 142678, 147645, 148946, 136924, 135857, 138087, 151643,
    158992, 157893, 164838, 174236, 178197, 176368, 166608, 170172, 187630, 170000, 172121, 182524,
    187623, 197093, 197561, 164831, 176372,
];

struct ZoomClient;

impl PostProcess for ZoomClient {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "zoom_client",
            order: 1083,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99935,
            "Missing the latest Zoom Client for Meetings",
            "Update to the latest Zoom Client for Meetings",
            "Zoom Client for Meetings Patch Rollup",
            PLUGIN_IDS_ZOOM_CLIENT,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &ZoomClient }
}

const PLUGIN_IDS_ZOOM_CLIENT: &[i32] = &[
    135188, 168792, 168821, 177219, 177223, 168797, 168807, 168816, 174469, 158168, 184369, 184371,
    184379, 190787, 184358, 184372, 184376, 185527, 185530, 185532, 185548, 190798, 184364, 184375,
    184365, 184366, 184378, 190784, 177220, 177221, 177231, 190797, 184359, 184361, 184367, 185525,
    185544, 185546, 190780, 190783, 190789, 190792, 190793, 190801, 193079, 177222, 177230, 177234,
    179598,
];

struct ZoomWorkplaceDesktopApp;

impl PostProcess for ZoomWorkplaceDesktopApp {
    fn info(&self) -> PostProcessInfo {
        PostProcessInfo {
            name: "zoom_workplace_desktop_app",
            order: 1084,
        }
    }
    fn run(&self, report: &mut NessusReport) {
        run_rollup(
            report,
            -99923,
            "Missing the latest Zoom Workplace Desktop App",
            "Update to the latest Zoom Workplace Desktop App",
            "Zoom Workplace Desktop App Patch Rollup",
            PLUGIN_IDS_ZOOM_WORKPLACE_DESKTOP_APP,
        );
    }
}

inventory::submit! {
    PluginEntry { plugin: &ZoomWorkplaceDesktopApp }
}

const PLUGIN_IDS_ZOOM_WORKPLACE_DESKTOP_APP: &[i32] = &[200481, 202591, 202593, 204852, 207228];
