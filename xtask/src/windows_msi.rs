//! The desktop client as a Windows Installer package (`.msi`), written with the `msi` and `cab` crates.
//!
//! What it does on Windows: a per-machine install of `crewcraft.exe` and the license files into
//! `Program Files\CrewCraft` (the folder can be changed with `INSTALLDIR=`), a Start menu shortcut, and an entry in
//! Installed apps (Add/Remove Programs) with the app icon. Every version has its own ProductCode under one fixed
//! UpgradeCode, and a newer package removes the older version before it installs (a major upgrade); a package older
//! than the installed version refuses to run. There are no dialogs: Windows shows its basic progress window.
//!
//! Every GUID except the UpgradeCode is a name-based (v5) UUID under the UpgradeCode, so the same version and
//! files always give the same package: the ProductCode from the version, each component's GUID from its file name
//! (stable across versions, as component rules require), and the PackageCode from the version and the cabinet.

use std::collections::BTreeSet;
use std::io::{Cursor, Write};
use std::time::{Duration, SystemTime};

use msi::{CodePage, Column, Insert, LanguageId, Package, PackageType, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::version::Version;
use crate::{Context, Error, Result};

/// The UpgradeCode shared by every CrewCraft desktop MSI, past and future. Never change it: Windows uses it to find
/// the installed version that a newer package replaces.
pub const UPGRADE_CODE: Uuid = uuid::uuid!("7B22B52D-5053-41BB-A254-FF039F9B37C3");

pub const PRODUCT_NAME: &str = "CrewCraft";
pub const MANUFACTURER: &str = "CrewCraft contributors";
/// The installed program's file name (and its File table key).
pub const EXE_NAME: &str = "crewcraft.exe";
/// The cabinet stream inside the package.
pub const CABINET: &str = "crewcraft.cab";
/// The icon's key in the Icon table.
pub const ICON: &str = "crewcraft.ico";
/// The public property that tells a newer package that an older version is installed.
pub const OLDER_FOUND: &str = "CREWCRAFT_OLDER_FOUND";
/// The public property that tells an older package that a newer version is installed.
pub const NEWER_FOUND: &str = "CREWCRAFT_NEWER_FOUND";
const LANGUAGE: u16 = 1033;

/// The GUID as Windows Installer writes it: uppercase, in braces.
pub fn guid(uuid: Uuid) -> String {
    uuid.braced().to_string().to_ascii_uppercase()
}

/// The ProductCode of a version: new for every version, the same every time that version is built.
pub fn product_code(version: &Version) -> Uuid {
    Uuid::new_v5(&UPGRADE_CODE, format!("ProductCode {version}").as_bytes())
}

/// The GUID of the component that installs `file_key`, the same in every version.
pub fn component_guid(file_key: &str) -> Uuid {
    Uuid::new_v5(&UPGRADE_CODE, format!("Component {file_key}").as_bytes())
}

/// The PackageCode: different whenever the version or any installed byte differs.
pub fn package_code(version: &Version, cabinet: &[u8]) -> Uuid {
    let digest: String = Sha256::digest(cabinet).iter().map(|byte| format!("{byte:02x}")).collect();
    Uuid::new_v5(&UPGRADE_CODE, format!("PackageCode {version} {digest}").as_bytes())
}

fn is_short_name(name: &str) -> bool {
    let (base, ext) = match name.rsplit_once('.') {
        Some((base, ext)) => (base, ext),
        None => (name, ""),
    };
    let plain = |part: &str| part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    (1..=8).contains(&base.len()) && ext.len() <= 3 && plain(base) && plain(ext) && !(name.ends_with('.'))
}

/// The `short|long` file name the File, Directory and Shortcut tables use. A name that is already a valid 8.3 name
/// is used as it is; otherwise the short name is the first letters and digits, `~N` and up to three extension
/// characters, unique (ignoring case) within `taken`.
pub fn short_long_name(long: &str, taken: &mut BTreeSet<String>) -> Result<String> {
    if long.is_empty() || long.contains(['|', '/', '\\', ':', '*', '?', '"', '<', '>']) {
        return Err(Error::new(format!("{long:?} cannot be an installed file name")));
    }
    if is_short_name(long) && taken.insert(long.to_ascii_lowercase()) {
        return Ok(long.to_string());
    }
    let (stem, ext) = match long.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, ext),
        _ => (long, ""),
    };
    let clean =
        |part: &str, len: usize| -> String { part.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_uppercase()).take(len).collect() };
    let ext = clean(ext, 3);
    let stem = clean(stem, 6);
    let stem = if stem.is_empty() { "FILE".to_string() } else { stem };
    for n in 1..100_000u32 {
        let suffix = format!("~{n}");
        let keep = 8usize.saturating_sub(suffix.len()).min(stem.len());
        let base = format!("{}{suffix}", &stem[..keep]);
        let short = if ext.is_empty() { base } else { format!("{base}.{ext}") };
        if taken.insert(short.to_ascii_lowercase()) {
            return Ok(format!("{short}|{long}"));
        }
    }
    Err(Error::new(format!("no free short name for {long:?}")))
}

/// A table key made from a file name: letters, digits, `_` and `.`, starting with a letter or `_`.
pub fn file_key(name: &str) -> String {
    let mut key: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' { c } else { '_' }).collect();
    if !key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        key.insert(0, '_');
    }
    key
}

/// What goes into the `.msi`.
pub struct MsiInput<'a> {
    pub version: &'a Version,
    /// `crewcraft.exe`, built for x86_64-pc-windows-gnu.
    pub exe: &'a [u8],
    /// License and notice files as `(installed file name, contents)`, installed beside the program.
    pub docs: &'a [(String, Vec<u8>)],
    /// The `.ico` for the shortcut and Installed apps.
    pub ico: &'a [u8],
    /// The time the cabinet's files and the summary information carry (the release's source date).
    pub mtime: u64,
}

fn s(text: &str) -> Value {
    Value::Str(text.to_string())
}

fn msi_error(what: &str) -> impl FnOnce(std::io::Error) -> Error + '_ {
    move |error| Error::new(format!("writing the MSI {what}: {error}"))
}

/// The cabinet holding the files, each named by its File table key, in File table sequence order.
pub fn cabinet(files: &[(String, &[u8])], mtime: u64) -> Result<Vec<u8>> {
    let seconds = i64::try_from(mtime).map_err(|_| Error::new("source date out of range"))?;
    let when = time::OffsetDateTime::from_unix_timestamp(seconds).context(|| "source date".to_string())?;
    let when = time::PrimitiveDateTime::new(when.date(), when.time());
    let mut builder = cab::CabinetBuilder::new();
    let folder = builder.add_folder(cab::CompressionType::MsZip);
    for (key, _) in files {
        folder.add_file(key.clone()).set_datetime(when);
    }
    let mut writer = builder.build(Cursor::new(Vec::new())).map_err(msi_error("cabinet"))?;
    let mut index = 0;
    while let Some(mut file) = writer.next_file().map_err(msi_error("cabinet"))? {
        let (_, data) = files.get(index).ok_or_else(|| Error::new("cabinet file count mismatch"))?;
        file.write_all(data).map_err(msi_error("cabinet"))?;
        index += 1;
    }
    Ok(writer.finish().map_err(msi_error("cabinet"))?.into_inner())
}

fn create<F: std::io::Read + Write + std::io::Seek>(package: &mut Package<F>, name: &str, columns: Vec<Column>, rows: Vec<Vec<Value>>) -> Result<()> {
    package.create_table(name, columns).map_err(msi_error(name))?;
    if !rows.is_empty() {
        package.insert_rows(Insert::into(name).rows(rows)).map_err(msi_error(name))?;
    }
    Ok(())
}

fn key(name: &str, len: usize) -> Column {
    Column::build(name).primary_key().id_string(len)
}

fn sequence_columns() -> Vec<Column> {
    vec![key("Action", 72), Column::build("Condition").nullable().string(255), Column::build("Sequence").nullable().int16()]
}

fn sequence_rows(actions: &[(&str, i32)]) -> Vec<Vec<Value>> {
    actions.iter().map(|(action, at)| vec![s(action), Value::Null, Value::Int(*at)]).collect()
}

/// The finished `.msi`.
pub fn build(input: &MsiInput<'_>) -> Result<Vec<u8>> {
    let version = input.version;
    let product_version = version.msi_product_version();

    // Files: the program first, then the documents, each in its own component.
    let mut files: Vec<(String, String, &[u8])> = vec![(file_key(EXE_NAME), EXE_NAME.to_string(), input.exe)];
    for (name, data) in input.docs {
        files.push((file_key(name), name.clone(), data));
    }
    let mut keys = BTreeSet::new();
    if let Some((duplicate, _, _)) = files.iter().find(|(key, _, _)| !keys.insert(key.to_ascii_lowercase())) {
        return Err(Error::new(format!("two installed files share the key {duplicate:?}")));
    }
    let cab_files: Vec<(String, &[u8])> = files.iter().map(|(key, _, data)| (key.clone(), *data)).collect();
    let cab = cabinet(&cab_files, input.mtime)?;
    let package_code = package_code(version, &cab);
    let file_count = i32::try_from(files.len()).map_err(|_| Error::new("too many files"))?;

    let mut package = Package::create(PackageType::Installer, Cursor::new(Vec::new())).map_err(msi_error("database"))?;
    package.set_database_codepage(CodePage::Windows1252);
    let saved = SystemTime::UNIX_EPOCH + Duration::from_secs(input.mtime);
    {
        let info = package.summary_info_mut();
        info.set_codepage(CodePage::Windows1252);
        info.set_title("Installation Database");
        info.set_subject(format!("{PRODUCT_NAME} {version}"));
        info.set_author(MANUFACTURER);
        info.set_keywords(&["Installer".to_string()]);
        info.set_comments(format!("Installs the {PRODUCT_NAME} desktop client, version {version}."));
        info.set_arch("x64");
        info.set_languages(&[LanguageId::from_id(LANGUAGE)]);
        info.set_uuid(package_code);
        // Schema 200: Windows Installer 2.0 or later, the minimum for a 64-bit package.
        info.set_page_count(200);
        // 2: long file names, files compressed in a cabinet.
        info.set_word_count(2);
        info.set_creating_application("cargo xtask dist (CrewCraft)");
        info.set_creation_time(saved);
        info.set_last_save_time(saved);
        // 2: read-only recommended.
        info.set_doc_security(2);
    }

    let mut install_names = BTreeSet::new();
    let install_dir = short_long_name(PRODUCT_NAME, &mut BTreeSet::new())?;
    let mut menu_names = BTreeSet::new();
    let shortcut_name = short_long_name(PRODUCT_NAME, &mut menu_names)?;

    create(
        &mut package,
        "Property",
        vec![key("Property", 72), Column::build("Value").localizable().text_string(0)],
        [
            ("ProductName", PRODUCT_NAME.to_string()),
            ("Manufacturer", MANUFACTURER.to_string()),
            ("ProductVersion", product_version.clone()),
            ("ProductCode", guid(product_code(version))),
            ("UpgradeCode", guid(UPGRADE_CODE)),
            ("ProductLanguage", LANGUAGE.to_string()),
            ("ALLUSERS", "1".to_string()),
            ("ARPPRODUCTICON", ICON.to_string()),
            ("ARPURLINFOABOUT", "https://github.com/SetsuaD/crewcraft-oss".to_string()),
            ("ARPHELPLINK", "https://github.com/SetsuaD/crewcraft-oss/issues".to_string()),
            ("ARPNOMODIFY", "1".to_string()),
            ("SecureCustomProperties", format!("{OLDER_FOUND};{NEWER_FOUND}")),
        ]
        .iter()
        .map(|(name, value)| vec![s(name), s(value)])
        .collect(),
    )?;

    create(
        &mut package,
        "Directory",
        vec![key("Directory", 72), Column::build("Directory_Parent").nullable().id_string(72), Column::build("DefaultDir").localizable().string(255)],
        vec![
            vec![s("TARGETDIR"), Value::Null, s("SourceDir")],
            vec![s("ProgramFiles64Folder"), s("TARGETDIR"), s("PFiles")],
            vec![s("INSTALLDIR"), s("ProgramFiles64Folder"), s(&install_dir)],
            vec![s("ProgramMenuFolder"), s("TARGETDIR"), s("Programs")],
        ],
    )?;

    let mut component_rows = Vec::new();
    let mut feature_component_rows = Vec::new();
    let mut file_rows = Vec::new();
    for (at, (file_key, name, data)) in files.iter().enumerate() {
        let component = format!("C_{file_key}");
        component_rows.push(vec![
            s(&component),
            s(&guid(component_guid(file_key))),
            s("INSTALLDIR"),
            // 256: a 64-bit component.
            Value::Int(256),
            Value::Null,
            s(file_key),
        ]);
        feature_component_rows.push(vec![s("Complete"), s(&component)]);
        let size = i32::try_from(data.len()).map_err(|_| Error::new(format!("{name} is too large for an MSI")))?;
        let sequence = i32::try_from(at + 1).map_err(|_| Error::new("too many files"))?;
        file_rows.push(vec![
            s(file_key),
            s(&component),
            s(&short_long_name(name, &mut install_names)?),
            Value::Int(size),
            Value::Null,
            Value::Null,
            // 512: vital (the install fails if the file cannot be installed).
            Value::Int(512),
            Value::Int(sequence),
        ]);
    }

    create(
        &mut package,
        "Component",
        vec![
            key("Component", 72),
            Column::build("ComponentId").nullable().string(38),
            Column::build("Directory_").id_string(72),
            Column::build("Attributes").int16(),
            Column::build("Condition").nullable().string(255),
            Column::build("KeyPath").nullable().id_string(72),
        ],
        component_rows,
    )?;
    create(
        &mut package,
        "Feature",
        vec![
            key("Feature", 38),
            Column::build("Feature_Parent").nullable().id_string(38),
            Column::build("Title").nullable().localizable().string(64),
            Column::build("Description").nullable().localizable().string(255),
            Column::build("Display").nullable().int16(),
            Column::build("Level").int16(),
            Column::build("Directory_").nullable().id_string(72),
            Column::build("Attributes").int16(),
        ],
        vec![vec![
            s("Complete"),
            Value::Null,
            s(PRODUCT_NAME),
            s("The CrewCraft desktop client."),
            Value::Int(1),
            Value::Int(1),
            s("INSTALLDIR"),
            Value::Int(0),
        ]],
    )?;
    create(&mut package, "FeatureComponents", vec![key("Feature_", 38), key("Component_", 72)], feature_component_rows)?;
    create(
        &mut package,
        "File",
        vec![
            key("File", 72),
            Column::build("Component_").id_string(72),
            Column::build("FileName").localizable().string(255),
            Column::build("FileSize").int32(),
            Column::build("Version").nullable().string(72),
            Column::build("Language").nullable().string(20),
            Column::build("Attributes").nullable().int16(),
            Column::build("Sequence").int16(),
        ],
        file_rows,
    )?;
    create(
        &mut package,
        "Media",
        vec![
            Column::build("DiskId").primary_key().int16(),
            Column::build("LastSequence").int16(),
            Column::build("DiskPrompt").nullable().localizable().string(64),
            Column::build("Cabinet").nullable().string(255),
            Column::build("VolumeLabel").nullable().string(32),
            Column::build("Source").nullable().string(72),
        ],
        vec![vec![Value::Int(1), Value::Int(file_count), Value::Null, s(&format!("#{CABINET}")), Value::Null, Value::Null]],
    )?;
    create(
        &mut package,
        "Shortcut",
        vec![
            key("Shortcut", 72),
            Column::build("Directory_").id_string(72),
            Column::build("Name").localizable().string(128),
            Column::build("Component_").id_string(72),
            Column::build("Target").string(72),
            Column::build("Arguments").nullable().string(255),
            Column::build("Description").nullable().localizable().string(255),
            Column::build("Hotkey").nullable().int16(),
            Column::build("Icon_").nullable().id_string(72),
            Column::build("IconIndex").nullable().int16(),
            Column::build("ShowCmd").nullable().int16(),
            Column::build("WkDir").nullable().id_string(72),
        ],
        vec![vec![
            s("StartMenuShortcut"),
            s("ProgramMenuFolder"),
            s(&shortcut_name),
            s(&format!("C_{}", file_key(EXE_NAME))),
            s(&format!("[#{}]", file_key(EXE_NAME))),
            Value::Null,
            s("Self-hosted team chat"),
            Value::Null,
            s(ICON),
            Value::Int(0),
            Value::Null,
            s("INSTALLDIR"),
        ]],
    )?;
    create(&mut package, "Icon", vec![key("Name", 72), Column::build("Data").binary()], vec![vec![s(ICON), Value::Binary]])?;
    create(
        &mut package,
        "Upgrade",
        vec![
            Column::build("UpgradeCode").primary_key().string(38),
            Column::build("VersionMin").primary_key().nullable().string(20),
            Column::build("VersionMax").primary_key().nullable().string(20),
            Column::build("Language").primary_key().nullable().string(255),
            Column::build("Attributes").primary_key().int32(),
            Column::build("Remove").nullable().string(255),
            Column::build("ActionProperty").id_string(72),
        ],
        vec![
            // Any older version (VersionMax exclusive): remove it, keeping its feature states. 1: migrate features.
            vec![s(&guid(UPGRADE_CODE)), Value::Null, s(&product_version), Value::Null, Value::Int(1), Value::Null, s(OLDER_FOUND)],
            // Any newer version (VersionMin exclusive): only detect it, so the launch condition refuses. 2: detect only.
            vec![s(&guid(UPGRADE_CODE)), s(&product_version), Value::Null, Value::Null, Value::Int(2), Value::Null, s(NEWER_FOUND)],
        ],
    )?;
    create(
        &mut package,
        "LaunchCondition",
        vec![Column::build("Condition").primary_key().string(255), Column::build("Description").localizable().string(255)],
        vec![
            vec![s(&format!("NOT {NEWER_FOUND}")), s("A newer version of CrewCraft is already installed.")],
            vec![s("VersionNT64"), s("CrewCraft needs 64-bit Windows.")],
        ],
    )?;
    let ui = [
        ("FindRelatedProducts", 25),
        ("LaunchConditions", 100),
        ("ValidateProductID", 700),
        ("CostInitialize", 800),
        ("FileCost", 900),
        ("CostFinalize", 1000),
        ("MigrateFeatureStates", 1200),
        ("ExecuteAction", 1300),
    ];
    let execute = [
        ("FindRelatedProducts", 25),
        ("LaunchConditions", 100),
        ("ValidateProductID", 700),
        ("CostInitialize", 800),
        ("FileCost", 900),
        ("CostFinalize", 1000),
        ("MigrateFeatureStates", 1200),
        ("InstallValidate", 1400),
        ("RemoveExistingProducts", 1401),
        ("InstallInitialize", 1500),
        ("ProcessComponents", 1600),
        ("UnpublishFeatures", 1800),
        ("RemoveShortcuts", 3200),
        ("RemoveFiles", 3500),
        ("InstallFiles", 4000),
        ("CreateShortcuts", 4500),
        ("RegisterUser", 6000),
        ("RegisterProduct", 6100),
        ("PublishFeatures", 6300),
        ("PublishProduct", 6400),
        ("InstallFinalize", 6600),
    ];
    let admin_ui = [("CostInitialize", 800), ("FileCost", 900), ("CostFinalize", 1000), ("ExecuteAction", 1300)];
    let admin_execute = [
        ("CostInitialize", 800),
        ("FileCost", 900),
        ("CostFinalize", 1000),
        ("InstallValidate", 1400),
        ("InstallInitialize", 1500),
        ("InstallAdminPackage", 3900),
        ("InstallFiles", 4000),
        ("InstallFinalize", 6600),
    ];
    create(&mut package, "InstallUISequence", sequence_columns(), sequence_rows(&ui))?;
    create(&mut package, "InstallExecuteSequence", sequence_columns(), sequence_rows(&execute))?;
    create(&mut package, "AdminUISequence", sequence_columns(), sequence_rows(&admin_ui))?;
    create(&mut package, "AdminExecuteSequence", sequence_columns(), sequence_rows(&admin_execute))?;

    {
        let mut stream = package.write_stream(&format!("Icon.{ICON}")).map_err(msi_error("icon"))?;
        stream.write_all(input.ico).map_err(msi_error("icon"))?;
    }
    {
        let mut stream = package.write_stream(CABINET).map_err(msi_error("cabinet stream"))?;
        stream.write_all(&cab).map_err(msi_error("cabinet stream"))?;
    }
    package.flush().map_err(msi_error("database"))?;
    Ok(package.into_inner().map_err(msi_error("database"))?.into_inner())
}
