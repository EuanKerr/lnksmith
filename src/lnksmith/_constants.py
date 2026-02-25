"""MS-SHLLINK constants and lookup tables shared by builder and parser."""

# ---------------------------------------------------------------------------
# ANSI code page
# ---------------------------------------------------------------------------
# The MS-SHLLINK spec defines ANSI string fields as encoded with the "system
# default code page" (the value returned by GetACP() on the creating system).
# On Western/English Windows this is CP-1252.  East Asian systems use CP-932
# (Japanese), CP-936 (Simplified Chinese), CP-949 (Korean), or CP-950
# (Traditional Chinese).  We default to CP-1252 since it is the most common
# target and a strict superset of ASCII.
ANSI_CODEPAGE = "cp1252"

# ---------------------------------------------------------------------------
# CLSIDs
# ---------------------------------------------------------------------------
LINK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

CLSID_MY_COMPUTER = b"\xe0\x4f\xd0\x20\xea\x3a\x69\x10\xa2\xd8\x08\x00\x2b\x30\x30\x9d"

CLSID_NETWORK = b"\x08\x02\x0c\x20\x08\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

# ---------------------------------------------------------------------------
# Extension block (BEEF0004)
# ---------------------------------------------------------------------------
EXT_SIG = 0xBEEF0004
EXT_VERSION = 9
EXT_HEADER_SIZE = 46  # fixed header before unicode name in v9

# ---------------------------------------------------------------------------
# ShowWindow commands (MS-SHLLINK 2.1.1)
# ---------------------------------------------------------------------------
SW_SHOWNORMAL = 1
SW_MAXIMIZED = 3
SW_MINIMIZED = 7

SHOW_CMD = {1: "SW_SHOWNORMAL", 3: "SW_MAXIMIZED", 7: "SW_MINIMIZED"}

# ---------------------------------------------------------------------------
# LinkFlags bit names
# ---------------------------------------------------------------------------
FLAG_NAMES = {
    0: "HasLinkTargetIDList",
    1: "HasLinkInfo",
    2: "HasName",
    3: "HasRelativePath",
    4: "HasWorkingDir",
    5: "HasArguments",
    6: "HasIconLocation",
    7: "IsUnicode",
    8: "ForceNoLinkInfo",
    9: "HasExpString",
    10: "RunInSeparateProcess",
    11: "Unused1",
    12: "HasDarwinID",
    13: "RunAsUser",
    14: "HasExpIcon",
    15: "NoPidlAlias",
    16: "Unused2",
    17: "RunWithShimLayer",
    18: "ForceNoLinkTrack",
    19: "EnableTargetMetadata",
    20: "DisableLinkPathTracking",
    21: "DisableKnownFolderTracking",
    22: "DisableKnownFolderAlias",
    23: "AllowLinkToLink",
    24: "UnaliasOnSave",
    25: "PreferEnvironmentPath",
    26: "KeepLocalIDListForUNCTarget",
}

# ---------------------------------------------------------------------------
# Hotkey modifier masks and virtual key names
# ---------------------------------------------------------------------------
HOTKEY_MOD = {0x01: "SHIFT", 0x02: "CTRL", 0x04: "ALT"}

VK_KEYS = {
    **{k: chr(k) for k in range(0x30, 0x3A)},  # 0-9
    **{k: chr(k) for k in range(0x41, 0x5B)},  # A-Z
    **{k: f"F{k - 0x6F}" for k in range(0x70, 0x88)},  # F1-F24
    **{k: f"NUMPAD{k - 0x60}" for k in range(0x60, 0x6A)},  # Numpad 0-9
    0x08: "BACKSPACE",
    0x09: "TAB",
    0x0D: "ENTER",
    0x1B: "ESC",
    0x20: "SPACE",
    0x21: "PAGEUP",
    0x22: "PAGEDOWN",
    0x23: "END",
    0x24: "HOME",
    0x25: "LEFT",
    0x26: "UP",
    0x27: "RIGHT",
    0x28: "DOWN",
    0x2D: "INSERT",
    0x2E: "DELETE",
    0x6A: "MULTIPLY",
    0x6B: "ADD",
    0x6D: "SUBTRACT",
    0x6E: "DECIMAL",
    0x6F: "DIVIDE",
}

# ---------------------------------------------------------------------------
# Drive types (VolumeID)
# ---------------------------------------------------------------------------
DRIVE_TYPES = {
    0: "UNKNOWN",
    1: "NO_ROOT_DIR",
    2: "REMOVABLE",
    3: "FIXED",
    4: "REMOTE",
    5: "CDROM",
    6: "RAMDISK",
}

# ---------------------------------------------------------------------------
# ExtraData block signatures (MS-SHLLINK 2.5)
# ---------------------------------------------------------------------------
EXTRA_SIGS = {
    0xA0000001: "EnvironmentVariableDataBlock",
    0xA0000002: "ConsoleDataBlock",
    0xA0000003: "TrackerDataBlock",
    0xA0000004: "ConsoleFEDataBlock",
    0xA0000005: "SpecialFolderDataBlock",
    0xA0000006: "DarwinDataBlock",
    0xA0000007: "IconEnvironmentDataBlock",
    0xA0000008: "ShimDataBlock",
    0xA0000009: "PropertyStoreDataBlock",
    0xA000000B: "KnownFolderDataBlock",
    0xA000000C: "VistaAndAboveIDListDataBlock",
}

# ---------------------------------------------------------------------------
# WNNC_NET_* Network Provider Types (CommonNetworkRelativeLink)
# ---------------------------------------------------------------------------
WNNC_NET_TYPES = {
    0x00020000: "WNNC_NET_LANMAN",
    0x00030000: "WNNC_NET_NETWARE",
    0x00090000: "WNNC_NET_9TILES",
    0x000B0000: "WNNC_NET_LOCUS",
    0x000D0000: "WNNC_NET_SUN_PC_NFS",
    0x00110000: "WNNC_NET_LANSTEP",
    0x00130000: "WNNC_NET_CLEARCASE",
    0x00140000: "WNNC_NET_FRONTIER",
    0x00150000: "WNNC_NET_BMC",
    0x00160000: "WNNC_NET_DCE",
    0x00170000: "WNNC_NET_AVID",
    0x00180000: "WNNC_NET_DOCUSPACE",
    0x00190000: "WNNC_NET_MANAGEWARE",
    0x001A0000: "WNNC_NET_OBJECT_DIRE",
    0x001B0000: "WNNC_NET_PATHWORKS",
    0x001C0000: "WNNC_NET_EXTENDNET",
    0x002B0000: "WNNC_NET_KNOWARE",
    0x003B0000: "WNNC_NET_DFS",
    0x003D0000: "WNNC_NET_MSFTP",
    0x00430000: "WNNC_NET_MS_NFS",
}

# ---------------------------------------------------------------------------
# Known Folder GUIDs (Windows 10/11)
# ---------------------------------------------------------------------------
KNOWN_FOLDER_GUIDS = {
    "Desktop": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
    "Documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
    "Downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
    "Music": "{4BD8D571-6D19-48D3-BE97-422220080E43}",
    "Pictures": "{33E28130-4E1E-4676-835A-98395C3BC3BB}",
    "Videos": "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}",
    "AppData": "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}",
    "LocalAppData": "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}",
    "ProgramFiles": "{905E63B6-C1BF-494E-B29C-65B732D3D21A}",
    "ProgramFilesX86": "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}",
    "System": "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}",
    "Windows": "{F38BF404-1D43-42F2-9305-67DE0B28FC23}",
    "Startup": "{B97D20BB-F46A-4C97-BA10-5E3608430854}",
    "SendTo": "{8983036C-27C0-404B-8F08-102D10DCFD74}",
    "Templates": "{A63293E8-664E-48DB-A079-DF759E0509F7}",
    "Fonts": "{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}",
    "OneDrive": "{A52BBA46-E9E1-435F-B3D9-28DAA648C0F6}",
    "Profile": "{5E6C858F-0E22-4760-9AFE-EA3317B67173}",
    "Public": "{DFDF76A2-C82A-4D63-906A-5644AC457385}",
    "PublicDesktop": "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}",
    "PublicDocuments": "{ED4824AF-DCE4-45A8-81E2-FC7965083634}",
    "Recent": "{AE50C081-EBD2-438A-8655-8A092E34987A}",
    "CommonStartMenu": "{A4115719-D62E-491D-AA7C-E74B8BE3B067}",
    "CommonPrograms": "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}",
    "AdminTools": "{724EF170-A42D-4FEF-9F26-B60E846FBA4F}",
    "ProgramData": "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}",
    "UserProfiles": "{0762D272-C50A-4BB0-A382-697DCD729B80}",
    "Favorites": "{1777F761-68AD-4D8A-87BD-30B759FA33DD}",
    "NetHood": "{C5ABBF53-E17F-4121-8900-86626FC2C973}",
    "PrintHood": "{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}",
}

# Reverse lookup: GUID -> friendly name
KNOWN_FOLDER_NAMES = {v: k for k, v in KNOWN_FOLDER_GUIDS.items()}

# ---------------------------------------------------------------------------
# VARIANT types used in Serialized Property Store
# ---------------------------------------------------------------------------
VT_TYPES = {
    0x0000: "VT_EMPTY",
    0x0002: "VT_I2",
    0x0003: "VT_I4",
    0x000B: "VT_BOOL",
    0x0013: "VT_UI4",
    0x0014: "VT_UI8",
    0x001E: "VT_LPSTR",
    0x001F: "VT_LPWSTR",
    0x0040: "VT_FILETIME",
    0x0041: "VT_BLOB",
    0x0042: "VT_STREAM",
    0x0048: "VT_CLSID",
    0x1002: "VT_VECTOR|VT_I2",
    0x1003: "VT_VECTOR|VT_I4",
    0x101F: "VT_VECTOR|VT_LPWSTR",
}

# ---------------------------------------------------------------------------
# Well-known Property Set Format IDs
# ---------------------------------------------------------------------------
PROPERTY_SET_GUIDS = {
    "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}": "SID_SPS_METADATA",
    "{46588AE2-4CBC-4338-BBFC-139326986DCE}": "SID_SPS_METADATA2",
    "{28636AA6-953D-11D2-B5D6-00C04FD918D0}": "System.Properties",
    "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}": "DocumentSummaryInformation",
    "{F29F85E0-4FF9-1068-AB91-08002B27B3D9}": "SummaryInformation",
    "{DABD30ED-0043-4B2E-87B4-6C698306D0D6}": "System.Volume",
    "{86D40B4D-9069-443C-8192-C1B02B9FF69C}": "System.Link",
    "{56A3372E-CE9C-11D2-9F0E-006097C686F6}": "System.Document",
}
