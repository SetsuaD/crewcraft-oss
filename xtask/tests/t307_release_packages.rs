//! T307: release packages. Checks the pure parts of `cargo xtask dist` from fake binaries, without building a
//! release: asset names and versions, SHA256SUMS.txt, the .deb layout, the server archives, the Depends mapping
//! and the MSI tables. Every archive is read back here with readers written for this test (or the msi and cab
//! crates), not with xtask's own code. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::PathBuf;

use md5::Md5;
use msi::{Package, PackageType, Select, Value};
use sha2::{Digest, Sha256};
use xtask::appimage;
use xtask::archive::{self, TreeFile};
use xtask::deb::{self, DebInput};
use xtask::dist;
use xtask::icon;
use xtask::linkage::{self, ElfLinks};
use xtask::macos;
use xtask::names::{Asset, SERVER, Target};
use xtask::sums;
use xtask::version::Version;
use xtask::windows_msi::{self, MsiInput};

/// 2026-01-01T00:00:00Z.
const MTIME: u64 = 1_767_225_600;
const SVG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../assets/icon/crewcraft.svg"));

fn version(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn fresh_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn docs() -> Vec<(String, Vec<u8>)> {
    vec![
        ("LICENSE-MIT".to_string(), b"synthetic MIT license text\n".to_vec()),
        ("LICENSE-APACHE".to_string(), b"synthetic Apache license text\n".to_vec()),
        ("NOTICE".to_string(), b"synthetic notice\n".to_vec()),
    ]
}

// ---------------------------------------------------------------- versions and names

#[test]
fn versions_are_written_per_format() {
    let beta = version("0.1.0-beta.1");
    assert_eq!(beta.to_string(), "0.1.0-beta.1");
    assert_eq!(beta.debian(), "0.1.0~beta.1");
    assert_eq!(beta.msi_product_version(), "0.1.201");
    assert_eq!(version("0.1.0").msi_product_version(), "0.1.900");
    assert_eq!(version("0.1.0").debian(), "0.1.0");
    assert_eq!(version("1.2.3-rc.4").msi_product_version(), "1.2.3304");
    assert_eq!(version("0.0.0-alpha.0").msi_product_version(), "0.0.100");

    for bad in [
        "",
        "0.1",
        "0.1.0.0", // a four-part version, not an address; sanitize-scan: allow
        "v0.1.0",
        "01.0.0",
        "0.01.0",
        "0.1.0-dev.1",
        "0.1.0-beta",
        "0.1.0-beta.100",
        "0.1.0-beta.01",
        "256.0.0",
        "0.1.65",
        "0.1.0+build",
    ] {
        assert!(Version::parse(bad).is_err(), "{bad:?} must be refused");
    }
}

#[test]
fn msi_versions_grow_with_releases() {
    let ordered = [
        "0.1.0-alpha.1",
        "0.1.0-alpha.99",
        "0.1.0-beta.0",
        "0.1.0-beta.1",
        "0.1.0-rc.1",
        "0.1.0",
        "0.1.1-alpha.0",
        "0.1.1",
        "0.1.64",
        "0.2.0-beta.1",
        "1.0.0",
    ];
    let numbers: Vec<Vec<u32>> =
        ordered.iter().map(|text| version(text).msi_product_version().split('.').map(|part| part.parse().unwrap()).collect()).collect();
    for pair in numbers.windows(2) {
        assert!(pair[0] < pair[1], "{:?} must be lower than {:?}", pair[0], pair[1]);
    }
    for number in &numbers {
        assert!(number[0] <= 255 && number[1] <= 255 && number[2] <= 65535);
    }
}

#[test]
fn asset_names_follow_the_pattern() {
    let v = version("0.1.0-beta.1");
    assert_eq!(Asset::ClientDeb.file_name(&v), "crewcraft-0.1.0-beta.1-linux-x86_64.deb");
    assert_eq!(Asset::ServerTarGz.file_name(&v), "crewcraft-server-0.1.0-beta.1-linux-x86_64.tar.gz");
    assert_eq!(Asset::ClientMsi.file_name(&v), "crewcraft-0.1.0-beta.1-windows-x86_64.msi");
    assert_eq!(Asset::ServerZip.file_name(&v), "crewcraft-server-0.1.0-beta.1-windows-x86_64.zip");
    assert_eq!(Asset::ClientAppImage.file_name(&v), "crewcraft-0.1.0-beta.1-linux-x86_64.AppImage");
    assert_eq!(Target::LinuxX86_64.assets(), [Asset::ClientDeb, Asset::ClientAppImage, Asset::ServerTarGz]);
    assert_eq!(Asset::ClientDmg.file_name(&v), "crewcraft-0.1.0-beta.1-macos-universal.dmg");
    assert_eq!(Asset::ServerMacTarGz.file_name(&v), "crewcraft-server-0.1.0-beta.1-macos-universal.tar.gz");
    assert_eq!(Target::LinuxX86_64.assets(), [Asset::ClientDeb, Asset::ClientAppImage, Asset::ServerTarGz]);
    assert_eq!(Target::WindowsX86_64.assets(), [Asset::ClientMsi, Asset::ServerZip]);
    assert_eq!(Target::MacosUniversal.assets(), [Asset::ClientDmg, Asset::ServerMacTarGz]);
    assert_eq!(Target::MacosUniversal.triples(), ["x86_64-apple-darwin", "aarch64-apple-darwin"]);
    assert_eq!(Target::parse("linux-x86_64").unwrap(), Target::LinuxX86_64);
    assert_eq!(Target::parse("windows-x86_64").unwrap(), Target::WindowsX86_64);
    assert_eq!(Target::parse("macos-universal").unwrap(), Target::MacosUniversal);
    assert!(Target::parse("macos-aarch64").is_err(), "macOS ships one universal package");
    assert!(Target::parse("windows").is_err());
}

#[test]
fn dist_arguments() {
    let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let both = dist::parse_args(&args(&["--version", "0.1.0-beta.0", "--out", "out"])).unwrap();
    assert_eq!(both.targets, Target::host_default());
    if !cfg!(target_os = "macos") {
        assert_eq!(both.targets, [Target::LinuxX86_64, Target::WindowsX86_64]);
    }
    assert_eq!(both.out, PathBuf::from("out"));
    let one = dist::parse_args(&args(&["--out", "o", "--target", "windows-x86_64", "--version", "0.1.0"])).unwrap();
    assert_eq!(one.targets, vec![Target::WindowsX86_64]);
    assert_eq!((both.appimage, both.appimage_runtime.as_ref()), (true, None));
    let runtime = dist::parse_args(&args(&["--version", "0.1.0", "--out", "o", "--appimage-runtime", "rt"])).unwrap();
    assert_eq!(runtime.appimage_runtime, Some(PathBuf::from("rt")));
    let without = dist::parse_args(&args(&["--version", "0.1.0", "--out", "o", "--no-appimage"])).unwrap();
    assert!(!without.appimage);
    assert!(dist::parse_args(&args(&["--version", "0.1.0", "--out", "o", "--no-appimage", "--appimage-runtime", "rt"])).is_err());
    assert!(dist::parse_args(&args(&["--out", "o"])).is_err());
    assert!(dist::parse_args(&args(&["--version", "0.1.0"])).is_err());
    assert!(dist::parse_args(&args(&["--version", "0.1.0", "--out", "o", "--sign"])).is_err());
    assert!(dist::parse_args(&args(&["--version", "0.1.0", "--out"])).is_err());
}

// ---------------------------------------------------------------- SHA256SUMS.txt

#[test]
fn sums_use_the_sha256sum_format() {
    let files = vec![("b.zip".to_string(), b"two".to_vec()), ("a.deb".to_string(), b"one".to_vec())];
    let expected = format!("{}  a.deb\n{}  b.zip\n", hex(&Sha256::digest(b"one")), hex(&Sha256::digest(b"two")));
    assert_eq!(sums::format_sums(&files).unwrap(), expected);
    assert_eq!(sums::sha256_hex(b"one"), hex(&Sha256::digest(b"one")));

    for bad in ["x/y", "a\nb", "a\\b", ""] {
        assert!(sums::format_sums(&[(bad.to_string(), vec![])]).is_err(), "{bad:?} must be refused");
    }
    let twice = vec![("a".to_string(), vec![1]), ("a".to_string(), vec![2])];
    assert!(sums::format_sums(&twice).is_err());
}

#[test]
fn sums_cover_every_asset_in_the_folder() {
    let dir = fresh_dir("t307-sums");
    std::fs::write(dir.join("crewcraft-0.1.0-linux-x86_64.deb"), b"deb").unwrap();
    std::fs::write(dir.join("crewcraft-0.1.0-windows-x86_64.msi"), b"msi").unwrap();
    std::fs::write(dir.join(".half-written.partial"), b"skip").unwrap();
    std::fs::write(dir.join(sums::SUMS_FILE), b"stale").unwrap();
    std::fs::create_dir(dir.join("subfolder")).unwrap();
    let text = sums::write_sums(&dir).unwrap();
    let expected = format!(
        "{}  crewcraft-0.1.0-linux-x86_64.deb\n{}  crewcraft-0.1.0-windows-x86_64.msi\n",
        hex(&Sha256::digest(b"deb")),
        hex(&Sha256::digest(b"msi"))
    );
    assert_eq!(text, expected);
    assert_eq!(std::fs::read_to_string(dir.join(sums::SUMS_FILE)).unwrap(), expected);
}

// ---------------------------------------------------------------- readers written for this test

/// `ar` members as (name, mtime, uid, gid, mode, data).
fn read_ar(data: &[u8]) -> Vec<(String, u64, u32, u32, u32, Vec<u8>)> {
    assert_eq!(&data[..8], b"!<arch>\n");
    let mut at = 8;
    let mut members = Vec::new();
    while at < data.len() {
        let header = std::str::from_utf8(&data[at..at + 60]).unwrap();
        assert_eq!(&header[58..60], "`\n");
        let field = |range: std::ops::Range<usize>| header[range].trim().to_string();
        let size: usize = field(48..58).parse().unwrap();
        let body = data[at + 60..at + 60 + size].to_vec();
        members.push((
            field(0..16),
            field(16..28).parse().unwrap(),
            field(28..34).parse().unwrap(),
            field(34..40).parse().unwrap(),
            u32::from_str_radix(&field(40..48), 8).unwrap(),
            body,
        ));
        at += 60 + size + size % 2;
    }
    members
}

#[derive(Debug)]
struct TarEntry {
    name: String,
    mode: u32,
    directory: bool,
    uid: u64,
    gid: u64,
    mtime: u64,
    owner: String,
    data: Vec<u8>,
}

fn octal(field: &[u8]) -> u64 {
    let text: String = field.iter().take_while(|&&b| b != 0 && b != b' ').map(|&b| b as char).collect();
    u64::from_str_radix(&text, 8).unwrap()
}

fn read_tar(data: &[u8]) -> Vec<TarEntry> {
    let mut entries = Vec::new();
    let mut at = 0;
    while at + 512 <= data.len() && data[at..at + 512].iter().any(|&b| b != 0) {
        let header = &data[at..at + 512];
        let mut copy = header.to_vec();
        copy[148..156].copy_from_slice(b"        ");
        assert_eq!(copy.iter().map(|&b| u64::from(b)).sum::<u64>(), octal(&header[148..156]), "tar header checksum");
        assert_eq!(&header[257..263], b"ustar\0");
        let name: String = header[..100].iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
        let size = octal(&header[124..136]) as usize;
        let owner: String = header[265..297].iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
        entries.push(TarEntry {
            name,
            mode: octal(&header[100..108]) as u32,
            directory: header[156] == b'5',
            uid: octal(&header[108..116]),
            gid: octal(&header[116..124]),
            mtime: octal(&header[136..148]),
            owner,
            data: data[at + 512..at + 512 + size].to_vec(),
        });
        at += 512 + size.div_ceil(512) * 512;
    }
    entries
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data).read_to_end(&mut out).unwrap();
    out
}

/// Every entry is owned by root, carries the fixed time, comes after its folder, and the list is sorted.
fn check_tree(entries: &[TarEntry]) {
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "entries are sorted");
    for (at, entry) in entries.iter().enumerate() {
        assert_eq!((entry.uid, entry.gid, entry.mtime, entry.owner.as_str()), (0, 0, MTIME, "root"), "{}", entry.name);
        assert_eq!(entry.directory, entry.name.ends_with('/'), "{}", entry.name);
        if entry.directory {
            assert_eq!(entry.mode, 0o755, "{}", entry.name);
        }
        let parent = entry.name.trim_end_matches('/').rsplit_once('/').map(|(parent, _)| format!("{parent}/"));
        if let Some(parent) = parent {
            assert!(names[..at].contains(&parent.as_str()), "{} comes after its folder {parent}", entry.name);
        }
    }
}

fn png_size(png: &[u8]) -> (u32, u32) {
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(&png[12..16], b"IHDR");
    (u32::from_be_bytes(png[16..20].try_into().unwrap()), u32::from_be_bytes(png[20..24].try_into().unwrap()))
}

// ---------------------------------------------------------------- the .deb

fn fake_deb(v: &Version, binary: &[u8]) -> Vec<u8> {
    let pngs = icon::render_sizes(SVG, &icon::HICOLOR_SIZES).unwrap();
    let depends = vec!["libc6 (>= 2.34)".to_string(), "libgcc-s1 (>= 4.2)".to_string()];
    deb::build(&DebInput {
        version: v,
        binary,
        depends: &depends,
        recommends: &deb::WINDOW_RECOMMENDS,
        svg: SVG,
        pngs: &pngs,
        docs: &docs(),
        mtime: MTIME,
    })
    .unwrap()
}

#[test]
fn deb_layout() {
    let v = version("0.1.0-beta.1");
    let binary = b"\x7fELF synthetic stand-in for the client binary\n".repeat(50);
    let deb = fake_deb(&v, &binary);
    assert_eq!(deb, fake_deb(&v, &binary), "the same input gives the same package");

    let members = read_ar(&deb);
    let names: Vec<&str> = members.iter().map(|m| m.0.as_str()).collect();
    assert_eq!(names, ["debian-binary", "control.tar.gz", "data.tar.gz"]);
    assert_eq!(members[0].5, b"2.0\n");
    for member in &members {
        assert_eq!((member.1, member.2, member.3, member.4), (MTIME, 0, 0, 0o100644), "{}", member.0);
    }

    // data.tar.gz
    let data = read_tar(&gunzip(&members[2].5));
    check_tree(&data);
    assert_eq!(data[0].name, "./");
    let files: BTreeMap<&str, &TarEntry> = data.iter().filter(|e| !e.directory).map(|e| (e.name.as_str(), e)).collect();
    let mut expected: Vec<String> = vec![
        "./usr/bin/crewcraft".into(),
        "./usr/share/applications/crewcraft.desktop".into(),
        "./usr/share/icons/hicolor/scalable/apps/crewcraft.svg".into(),
        "./usr/share/doc/crewcraft/copyright".into(),
        "./usr/share/doc/crewcraft/LICENSE-MIT".into(),
        "./usr/share/doc/crewcraft/LICENSE-APACHE".into(),
        "./usr/share/doc/crewcraft/NOTICE".into(),
    ];
    for size in icon::HICOLOR_SIZES {
        expected.push(format!("./usr/share/icons/hicolor/{size}x{size}/apps/crewcraft.png"));
    }
    expected.sort();
    assert_eq!(files.keys().copied().collect::<Vec<_>>(), expected);

    let program = files["./usr/bin/crewcraft"];
    assert_eq!((program.mode, &program.data), (0o755, &binary));
    for (name, entry) in &files {
        if *name != "./usr/bin/crewcraft" {
            assert_eq!(entry.mode, 0o644, "{name}");
        }
    }
    assert_eq!(files["./usr/share/icons/hicolor/scalable/apps/crewcraft.svg"].data, SVG);
    assert_eq!(files["./usr/share/doc/crewcraft/NOTICE"].data, b"synthetic notice\n");
    for size in icon::HICOLOR_SIZES {
        let png = &files[format!("./usr/share/icons/hicolor/{size}x{size}/apps/crewcraft.png").as_str()].data;
        assert_eq!(png_size(png), (size, size));
    }
    let desktop = String::from_utf8(files["./usr/share/applications/crewcraft.desktop"].data.clone()).unwrap();
    for line in ["[Desktop Entry]", "Type=Application", "Name=CrewCraft", "Exec=crewcraft", "Icon=crewcraft", "StartupWMClass=crewcraft"] {
        assert!(desktop.lines().any(|l| l == line), "desktop entry has {line}");
    }

    // control.tar.gz
    let control_tar = read_tar(&gunzip(&members[1].5));
    check_tree(&control_tar);
    let control_names: Vec<&str> = control_tar.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(control_names, ["./", "./control", "./md5sums"]);
    let control = String::from_utf8(control_tar[1].data.clone()).unwrap();
    let fields: BTreeMap<&str, &str> = control.lines().filter(|l| !l.starts_with(' ')).filter_map(|l| l.split_once(": ")).collect();
    assert_eq!(fields["Package"], "crewcraft");
    assert_eq!(fields["Version"], "0.1.0~beta.1");
    assert_eq!(fields["Architecture"], "amd64");
    assert_eq!(fields["Depends"], "libc6 (>= 2.34), libgcc-s1 (>= 4.2)");
    assert_eq!(fields["Recommends"], deb::WINDOW_RECOMMENDS.join(", "));
    assert!(fields.contains_key("Maintainer") && fields.contains_key("Description") && fields.contains_key("Section"));
    let folders = data.iter().filter(|e| e.directory && e.name != "./").count() as u64;
    let kib: u64 = files.values().map(|e| (e.data.len() as u64).div_ceil(1024)).sum::<u64>() + folders;
    assert_eq!(fields["Installed-Size"], kib.to_string());
    assert!(control.ends_with('\n') && !control.contains("\n\n"));

    let md5sums = String::from_utf8(control_tar[2].data.clone()).unwrap();
    let listed: BTreeMap<String, String> =
        md5sums.lines().map(|l| l.split_once("  ").unwrap()).map(|(sum, path)| (format!("./{path}"), sum.to_string())).collect();
    assert_eq!(listed.keys().cloned().collect::<Vec<_>>(), expected);
    for (path, sum) in &listed {
        assert_eq!(*sum, hex(&Md5::digest(&files[path.as_str()].data)), "{path}");
    }
}

#[test]
fn deb_refuses_a_bad_relation() {
    let v = version("0.1.0");
    let depends = vec!["libc6, libevil".to_string()];
    let input = DebInput { version: &v, binary: b"x", depends: &depends, recommends: &[], svg: SVG, pngs: &[], docs: &[], mtime: MTIME };
    assert!(deb::build(&input).is_err());
}

// ---------------------------------------------------------------- the AppImage

#[test]
fn appimage_appdir_and_runtime() {
    let v = version("0.1.0-beta.1");
    let binary = b"\x7fELF synthetic stand-in for the client binary\n".repeat(20);
    let pngs = icon::render_sizes(SVG, &icon::HICOLOR_SIZES).unwrap();
    let top = icon::render_png(SVG, appimage::TOP_ICON_SIZE).unwrap();
    let docs = docs();
    let input = DebInput { version: &v, binary: &binary, depends: &[], recommends: &[], svg: SVG, pngs: &pngs, docs: &docs, mtime: MTIME };
    let runtime_license = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../assets/appimage/RUNTIME-LICENSE.txt"));
    let lgpl = b"synthetic stand-in for the LGPL 2.1 text\n";
    let files = appimage::appdir_files(&input, &top, runtime_license, lgpl);
    let by_path: BTreeMap<&str, &TreeFile> = files.iter().map(|f| (f.path.as_str(), f)).collect();

    // The top of the AppDir: what the runtime starts and what desktop integration reads.
    assert_eq!((by_path["AppRun"].mode, &by_path["AppRun"].data), (0o755, &binary));
    assert_eq!(by_path["crewcraft.desktop"].data, deb::DESKTOP_ENTRY.as_bytes());
    assert_eq!(png_size(&by_path["crewcraft.png"].data), (256, 256));
    assert_eq!(by_path[".DirIcon"].data, by_path["crewcraft.png"].data);
    // Below it, the same files as the .deb.
    for file in deb::data_files(&input) {
        assert_eq!(by_path[file.path.as_str()], &file, "{}", file.path);
    }
    assert_eq!(files.len(), deb::data_files(&input).len() + 7);
    let desktop = deb::DESKTOP_ENTRY;
    let icon_name = desktop.lines().find_map(|l| l.strip_prefix("Icon=")).unwrap();
    assert!(by_path.contains_key(format!("{icon_name}.png").as_str()), "the desktop entry's icon is at the top");
    assert!(desktop.lines().any(|l| l == "StartupWMClass=crewcraft"), "the window's app id matches the desktop entry");

    // The runtime's licenses travel with it: its MIT license, the LGPL 2.1 for libfuse, and where its source is.
    let license = by_path["usr/share/licenses/appimage-runtime/LICENSE"];
    assert_eq!((license.mode, license.data.as_slice()), (0o644, runtime_license.as_slice()));
    let license_text = String::from_utf8(license.data.clone()).unwrap();
    assert!(license_text.starts_with("MIT License") && license_text.contains("libfuse"));
    assert_eq!(by_path["usr/share/licenses/appimage-runtime/LGPL-2.1"].data, lgpl);
    let source = String::from_utf8(by_path["usr/share/licenses/appimage-runtime/SOURCE.txt"].data.clone()).unwrap();
    for needed in [
        "https://github.com/AppImage/type2-runtime/releases/tag/20251108",
        "https://github.com/AppImage/type2-runtime/tree/20251108",
        appimage::RUNTIME_SHA256,
        "LGPL 2.1",
        "--appimage-extract",
    ] {
        assert!(source.contains(needed), "SOURCE.txt names {needed}");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("t307-appdir").join("AppDir");
        appimage::write_appdir(&dir, &files).unwrap();
        let mode = |p: &str| std::fs::metadata(dir.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(""), 0o755);
        assert_eq!(mode("AppRun"), 0o755);
        assert_eq!(mode("usr/bin/crewcraft"), 0o755);
        assert_eq!(mode("usr/share/icons/hicolor"), 0o755);
        assert_eq!(mode("crewcraft.desktop"), 0o644);
        assert_eq!(std::fs::read(dir.join("usr/bin/crewcraft")).unwrap(), binary);
        assert!(appimage::write_appdir(&dir, &files).is_err(), "the AppDir must be a new folder");
    }

    // The runtime is pinned: anything else is refused before use.
    assert!(appimage::check_runtime(b"\x7fELF some other runtime").is_err());
    assert_eq!(appimage::RUNTIME_SHA256.len(), 64);
    assert_eq!(appimage::assemble(b"RUNTIME", b"hsqs IMAGE"), b"RUNTIMEhsqs IMAGE");
}

// ---------------------------------------------------------------- macOS (the parts that do not need a Mac)

/// The plist's keys and values; `<true/>` reads as "true".
fn plist_entries(text: &str) -> BTreeMap<String, String> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let mut entries = BTreeMap::new();
    for pair in lines.windows(2) {
        if let Some(key) = pair[0].strip_prefix("<key>").and_then(|k| k.strip_suffix("</key>")) {
            let value = match pair[1] {
                "<true/>" => "true".to_string(),
                other => other.strip_prefix("<string>").and_then(|v| v.strip_suffix("</string>")).unwrap().to_string(),
            };
            assert!(entries.insert(key.to_string(), value).is_none(), "{key} is listed once");
        }
    }
    entries
}

#[test]
fn macos_info_plist() {
    let v = version("0.1.0-beta.1");
    let text = macos::info_plist(&v);
    assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist"));
    assert!(text.contains("<plist version=\"1.0\">\n<dict>\n") && text.ends_with("</dict>\n</plist>\n"));
    let entries = plist_entries(&text);
    assert_eq!(entries["CFBundleIdentifier"], "io.github.setsuad.crewcraft");
    assert_eq!(entries["CFBundleName"], "CrewCraft");
    assert_eq!(entries["CFBundleExecutable"], "crewcraft");
    assert_eq!(entries["CFBundlePackageType"], "APPL");
    assert_eq!(entries["CFBundleShortVersionString"], "0.1.0-beta.1");
    assert_eq!(entries["CFBundleVersion"], "0.1.201");
    assert_eq!(entries["CFBundleIconFile"], "crewcraft.icns");
    assert_eq!(entries["LSMinimumSystemVersion"], "11.0");
    assert_eq!(entries["NSHighResolutionCapable"], "true");
    assert_eq!(plist_entries(&macos::info_plist(&version("0.1.0")))["CFBundleVersion"], "0.1.900");
}

#[test]
fn macos_icns_holds_every_size() {
    let icns = macos::render_icns(SVG).unwrap();
    assert_eq!(&icns[..4], b"icns");
    assert_eq!(u32::from_be_bytes(icns[4..8].try_into().unwrap()) as usize, icns.len());
    let mut at = 8;
    let mut found = Vec::new();
    while at < icns.len() {
        let kind = std::str::from_utf8(&icns[at..at + 4]).unwrap().to_string();
        let len = u32::from_be_bytes(icns[at + 4..at + 8].try_into().unwrap()) as usize;
        found.push((kind, png_size(&icns[at + 8..at + len]).0));
        at += len;
    }
    assert_eq!(at, icns.len());
    let expected = [
        ("icp4", 16),
        ("icp5", 32),
        ("ic11", 32),
        ("ic12", 64),
        ("ic07", 128),
        ("ic13", 256),
        ("ic08", 256),
        ("ic14", 512),
        ("ic09", 512),
        ("ic10", 1024),
    ];
    assert_eq!(found, expected.map(|(k, s)| (k.to_string(), s)));
}

#[test]
fn macos_app_bundle_and_staging() {
    let v = version("0.1.0-beta.1");
    let binary = b"\xcf\xfa\xed\xfe synthetic stand-in for the universal client".to_vec();
    let app = macos::app_files(&v, &binary, b"icns-bytes", &docs());
    let paths: Vec<&str> = app.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "CrewCraft.app/Contents/Info.plist",
            "CrewCraft.app/Contents/MacOS/crewcraft",
            "CrewCraft.app/Contents/PkgInfo",
            "CrewCraft.app/Contents/Resources/crewcraft.icns",
            "CrewCraft.app/Contents/Resources/licenses/LICENSE-APACHE",
            "CrewCraft.app/Contents/Resources/licenses/LICENSE-MIT",
            "CrewCraft.app/Contents/Resources/licenses/NOTICE",
        ]
    );
    let program = &app[1];
    assert_eq!((program.mode, &program.data), (0o755, &binary));
    assert_eq!(app[2].data, b"APPL????");
    assert_eq!(app[0].data, macos::info_plist(&v).into_bytes());

    #[cfg(unix)]
    {
        let dir = fresh_dir("t307-dmg").join("CrewCraft");
        macos::write_staging(&dir, &app).unwrap();
        let mut top: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        top.sort();
        assert_eq!(top, ["Applications", "CrewCraft.app"]);
        assert_eq!(std::fs::read_link(dir.join("Applications")).unwrap(), PathBuf::from("/Applications"));
        assert_eq!(std::fs::read(dir.join("CrewCraft.app/Contents/MacOS/crewcraft")).unwrap(), binary);
    }

    // The Apple tools run only on a Mac; anywhere else the target stops before building anything.
    if cfg!(target_os = "macos") {
        assert!(macos::require_macos().is_ok());
    } else {
        assert!(macos::require_macos().is_err());
    }
    assert!(linkage::check_macho(b"\x7fELF not a Mach-O file", "aarch64-apple-darwin").is_err());
}

// ---------------------------------------------------------------- Depends and Windows imports

#[test]
fn depends_come_from_what_the_binary_links() {
    let pair = |a: &str, b: &str| (a.to_string(), b.to_string());
    let links = ElfLinks {
        needed: vec!["libgcc_s.so.1".into(), "libm.so.6".into(), "libc.so.6".into()],
        versions: vec![
            pair("libc.so.6", "GLIBC_2.2.5"),
            pair("libc.so.6", "GLIBC_2.34"),
            pair("libm.so.6", "GLIBC_2.29"),
            pair("libc.so.6", "GLIBC_2.3.4"),
            pair("libgcc_s.so.1", "GCC_3.0"),
            pair("libgcc_s.so.1", "GCC_4.2.0"),
        ],
    };
    assert_eq!(linkage::debian_depends(&links).unwrap(), ["libc6 (>= 2.34)", "libgcc-s1 (>= 4.2.0)"]);

    let plain = ElfLinks { needed: vec!["libc.so.6".into()], versions: vec![] };
    assert_eq!(linkage::debian_depends(&plain).unwrap(), ["libc6"]);

    let unknown = ElfLinks { needed: vec!["libc.so.6".into(), "libexample.so.1".into()], versions: vec![] };
    assert!(linkage::debian_depends(&unknown).is_err(), "an unmapped library fails the build");
    let private = ElfLinks { needed: vec!["libc.so.6".into()], versions: vec![pair("libc.so.6", "GLIBC_PRIVATE")] };
    assert!(linkage::debian_depends(&private).is_err());

    assert!(linkage::elf_links(b"not an ELF file").is_err());
    assert!(linkage::pe_imports(b"MZ not a PE file").is_err());
    let system = ["bcrypt.dll", "kernel32.dll", "ntdll.dll", "ws2_32.dll"].map(String::from);
    assert!(linkage::check_windows_imports(&system).is_ok());
    let mingw = ["kernel32.dll", "libgcc_s_seh-1.dll"].map(String::from);
    assert!(linkage::check_windows_imports(&mingw).is_err());
}

// ---------------------------------------------------------------- server archives

#[test]
fn linux_server_archive() {
    let v = version("0.1.0-beta.1");
    let binary = b"\x7fELF synthetic server\n".to_vec();
    let files = dist::server_files(SERVER, &binary, &docs(), dist::SERVER_README);
    let prefix = format!("{}/", Asset::ServerTarGz.stem(&v));
    assert_eq!(prefix, "crewcraft-server-0.1.0-beta.1-linux-x86_64/");
    let tar = archive::tar_gz(&files, &prefix, MTIME).unwrap();
    assert_eq!(tar, archive::tar_gz(&files, &prefix, MTIME).unwrap());
    let entries = read_tar(&gunzip(&tar));
    check_tree(&entries);
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    let expected: Vec<String> =
        ["", "LICENSE-APACHE", "LICENSE-MIT", "NOTICE", "README.txt", "crewcraft-server"].iter().map(|n| format!("{prefix}{n}")).collect();
    assert_eq!(names, expected);
    let server = entries.iter().find(|e| e.name.ends_with("/crewcraft-server")).unwrap();
    assert_eq!((server.mode, &server.data), (0o755, &binary));
    let readme = String::from_utf8(entries.iter().find(|e| e.name.ends_with("README.txt")).unwrap().data.clone()).unwrap();
    assert!(readme.contains("crewcraft-server first-run") && readme.contains("crewcraft-server serve"));
}

/// Zip entries as (name, unix mode, data), checked against the local headers and CRCs.
fn read_zip(data: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
    let u16_at = |at: usize| u16::from_le_bytes([data[at], data[at + 1]]) as usize;
    let u32_at = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
    let end = data.len() - 22;
    assert_eq!(u32_at(end), 0x0605_4b50);
    let count = u16_at(end + 10);
    let mut at = u32_at(end + 16) as usize;
    let mut entries = Vec::new();
    for _ in 0..count {
        assert_eq!(u32_at(at), 0x0201_4b50);
        let method = u16_at(at + 10);
        let crc = u32_at(at + 16);
        let compressed = u32_at(at + 20) as usize;
        let size = u32_at(at + 24) as usize;
        let name_len = u16_at(at + 28);
        let extra = u16_at(at + 30);
        let comment = u16_at(at + 32);
        let mode = u32_at(at + 38) >> 16;
        let local = u32_at(at + 42) as usize;
        let name = String::from_utf8(data[at + 46..at + 46 + name_len].to_vec()).unwrap();
        assert_eq!(u32_at(local), 0x0403_4b50);
        assert_eq!(&data[local + 30..local + 30 + name_len], name.as_bytes());
        let body = &data[local + 30 + name_len + u16_at(local + 28)..][..compressed];
        let content = match method {
            0 => body.to_vec(),
            8 => {
                let mut out = Vec::new();
                flate2::read::DeflateDecoder::new(body).read_to_end(&mut out).unwrap();
                out
            }
            other => panic!("unexpected zip method {other}"),
        };
        assert_eq!(content.len(), size);
        let mut check = flate2::Crc::new();
        check.update(&content);
        assert_eq!(check.sum(), crc, "{name}");
        entries.push((name, mode, content));
        at += 46 + name_len + extra + comment;
    }
    entries
}

#[test]
fn windows_server_archive() {
    let v = version("0.1.0-beta.1");
    let exe = b"MZ synthetic server program".repeat(40);
    let docs: Vec<(String, Vec<u8>)> = docs().into_iter().map(|(name, data)| (format!("{name}.txt"), data)).collect();
    let files = dist::server_files("crewcraft-server.exe", &exe, &docs, dist::SERVER_README);
    let prefix = format!("{}/", Asset::ServerZip.stem(&v));
    let zip = archive::zip(&files, &prefix, MTIME).unwrap();
    assert_eq!(zip, archive::zip(&files, &prefix, MTIME).unwrap());
    let entries = read_zip(&zip);
    let names: Vec<&str> = entries.iter().map(|e| e.0.as_str()).collect();
    let expected: Vec<String> = ["", "LICENSE-APACHE.txt", "LICENSE-MIT.txt", "NOTICE.txt", "README.txt", "crewcraft-server.exe"]
        .iter()
        .map(|n| format!("crewcraft-server-0.1.0-beta.1-windows-x86_64/{n}"))
        .collect();
    assert_eq!(names, expected);
    assert_eq!(entries[0].1, 0o40755);
    let program = entries.iter().find(|e| e.0.ends_with(".exe")).unwrap();
    assert_eq!((program.1, &program.2), (0o100755, &exe));
    assert_eq!(entries.iter().find(|e| e.0.ends_with("NOTICE.txt")).unwrap().1, 0o100644);
}

// ---------------------------------------------------------------- the MSI

fn fake_msi(v: &Version, exe: &[u8]) -> Vec<u8> {
    let ico = icon::ico(&icon::render_sizes(SVG, &icon::ICO_SIZES).unwrap()).unwrap();
    let docs: Vec<(String, Vec<u8>)> = docs().into_iter().map(|(name, data)| (format!("{name}.txt"), data)).collect();
    windows_msi::build(&MsiInput { version: v, exe, docs: &docs, ico: &ico, mtime: MTIME }).unwrap()
}

fn rows(package: &mut Package<Cursor<Vec<u8>>>, table: &str) -> Vec<Vec<Value>> {
    let rows = package.select_rows(Select::table(table)).unwrap();
    rows.map(|row| (0..row.len()).map(|i| row[i].clone()).collect()).collect()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_else(|| panic!("expected a string, found {value:?}"))
}

fn properties(package: &mut Package<Cursor<Vec<u8>>>) -> BTreeMap<String, String> {
    rows(package, "Property").iter().map(|row| (text(&row[0]).to_string(), text(&row[1]).to_string())).collect()
}

fn find<'a>(rows: &'a [Vec<Value>], key: &str) -> &'a Vec<Value> {
    rows.iter().find(|row| row[0].as_str() == Some(key)).unwrap_or_else(|| panic!("no row {key}"))
}

#[test]
fn msi_tables() {
    let v = version("0.1.0-beta.1");
    let exe = b"MZ synthetic client program".repeat(100);
    let bytes = fake_msi(&v, &exe);
    assert_eq!(bytes, fake_msi(&v, &exe), "the same input gives the same package");
    let mut package = Package::open(Cursor::new(bytes)).unwrap();
    assert_eq!(package.package_type(), PackageType::Installer);

    let info = package.summary_info();
    assert_eq!(info.arch(), Some("x64"));
    assert_eq!(info.languages().iter().map(|l| l.id()).collect::<Vec<_>>(), [1033]);
    assert_eq!(info.page_count(), Some(200));
    assert_eq!(info.word_count(), Some(2), "long names, compressed files");
    let package_code = info.uuid().unwrap();

    let props = properties(&mut package);
    assert_eq!(props["ProductName"], "CrewCraft");
    assert_eq!(props["Manufacturer"], "CrewCraft contributors");
    assert_eq!(props["ProductVersion"], "0.1.201");
    // Fixed forever: a different UpgradeCode would install side by side instead of upgrading.
    assert_eq!(props["UpgradeCode"], "{7B22B52D-5053-41BB-A254-FF039F9B37C3}");
    assert_eq!(props["ProductCode"], windows_msi::guid(windows_msi::product_code(&v)));
    assert_eq!(props["ALLUSERS"], "1");
    assert_eq!(props["ARPPRODUCTICON"], windows_msi::ICON);
    let secure: Vec<&str> = props["SecureCustomProperties"].split(';').collect();

    let dirs = rows(&mut package, "Directory");
    let install = find(&dirs, "INSTALLDIR");
    assert_eq!(text(&install[1]), "ProgramFiles64Folder");
    assert!(text(&install[2]).rsplit('|').next() == Some("CrewCraft"));
    assert_eq!(text(&find(&dirs, "ProgramFiles64Folder")[1]), "TARGETDIR");
    assert_eq!(text(&find(&dirs, "ProgramMenuFolder")[1]), "TARGETDIR");

    let files = rows(&mut package, "File");
    assert_eq!(files.len(), 4);
    let program = find(&files, "crewcraft.exe");
    assert_eq!(text(&program[2]).rsplit('|').next(), Some("crewcraft.exe"));
    assert_eq!(program[3], Value::Int(exe.len() as i32));
    assert_eq!(program[7], Value::Int(1));
    let long_names: Vec<&str> = files.iter().map(|row| text(&row[2]).rsplit('|').next().unwrap()).collect();
    for name in ["LICENSE-MIT.txt", "LICENSE-APACHE.txt", "NOTICE.txt"] {
        assert!(long_names.contains(&name), "{name} is installed");
    }
    let mut sequences: Vec<i32> = files.iter().map(|row| row[7].as_int().unwrap()).collect();
    sequences.sort();
    assert_eq!(sequences, [1, 2, 3, 4]);

    let components = rows(&mut package, "Component");
    let component = components.iter().find(|row| row[5].as_str() == Some("crewcraft.exe")).unwrap();
    assert_eq!(text(&component[0]), text(&program[1]));
    assert_eq!(text(&component[2]), "INSTALLDIR");
    assert_eq!(component[3].as_int().unwrap() & 256, 256, "a 64-bit component");
    let component_id = text(&component[1]).to_string();
    assert!(component_id.starts_with('{') && component_id.ends_with('}') && component_id.len() == 38);
    assert_eq!(rows(&mut package, "FeatureComponents").len(), 4);

    let media = rows(&mut package, "Media");
    assert_eq!(media.len(), 1);
    assert_eq!(media[0][1], Value::Int(4));
    assert_eq!(text(&media[0][3]), format!("#{}", windows_msi::CABINET));

    let shortcuts = rows(&mut package, "Shortcut");
    assert_eq!(shortcuts.len(), 1);
    assert_eq!(text(&shortcuts[0][1]), "ProgramMenuFolder");
    assert_eq!(text(&shortcuts[0][2]).rsplit('|').next(), Some("CrewCraft"));
    assert_eq!(text(&shortcuts[0][4]), "[#crewcraft.exe]");

    let upgrades = rows(&mut package, "Upgrade");
    assert_eq!(upgrades.len(), 2);
    for row in &upgrades {
        assert_eq!(text(&row[0]), "{7B22B52D-5053-41BB-A254-FF039F9B37C3}");
        assert!(secure.contains(&text(&row[6])), "the upgrade property is secure");
    }
    let older = upgrades.iter().find(|row| row[2].as_str() == Some("0.1.201")).unwrap();
    assert_eq!((older[1].is_null(), older[4].as_int().unwrap() & (2 | 512)), (true, 0), "removes strictly older versions");
    let newer = upgrades.iter().find(|row| row[1].as_str() == Some("0.1.201")).unwrap();
    assert_eq!((newer[2].is_null(), newer[4].as_int().unwrap() & (2 | 256)), (true, 2), "only detects strictly newer versions");
    let conditions = rows(&mut package, "LaunchCondition");
    assert!(conditions.iter().any(|row| text(&row[0]) == format!("NOT {}", text(&newer[6]))), "a newer version stops the install");

    let execute = rows(&mut package, "InstallExecuteSequence");
    let at = |action: &str| find(&execute, action)[2].as_int().unwrap();
    assert!(at("FindRelatedProducts") < at("LaunchConditions"));
    assert!(at("InstallValidate") < at("RemoveExistingProducts") && at("RemoveExistingProducts") < at("InstallInitialize"));
    assert!(at("InstallInitialize") < at("InstallFiles") && at("InstallFiles") < at("CreateShortcuts"));
    assert!(at("RegisterProduct") < at("PublishProduct") && at("PublishProduct") < at("InstallFinalize"));
    let ui = rows(&mut package, "InstallUISequence");
    assert!(ui.iter().any(|row| row[0].as_str() == Some("ExecuteAction")));

    // The embedded cabinet holds every file under its key; the icon is an .ico.
    let mut cab_bytes = Vec::new();
    package.read_stream(windows_msi::CABINET).unwrap().read_to_end(&mut cab_bytes).unwrap();
    let mut cabinet = cab::Cabinet::new(Cursor::new(cab_bytes.clone())).unwrap();
    let mut from_cab = Vec::new();
    cabinet.read_file("crewcraft.exe").unwrap().read_to_end(&mut from_cab).unwrap();
    assert_eq!(from_cab, exe);
    for row in &files {
        assert!(cabinet.get_file_entry(text(&row[0])).is_some(), "{} is in the cabinet", text(&row[0]));
    }
    assert_eq!(package_code, windows_msi::package_code(&v, &cab_bytes));
    let mut ico = Vec::new();
    package.read_stream(&format!("Icon.{}", windows_msi::ICON)).unwrap().read_to_end(&mut ico).unwrap();
    assert_eq!(&ico[..4], [0, 0, 1, 0]);

    // The next version: new ProductCode and PackageCode, same UpgradeCode and component GUIDs.
    let next = version("0.1.0-beta.2");
    let mut later = Package::open(Cursor::new(fake_msi(&next, &exe))).unwrap();
    let later_code = later.summary_info().uuid().unwrap();
    let later_props = properties(&mut later);
    assert_ne!(later_props["ProductCode"], props["ProductCode"]);
    assert_eq!(later_props["UpgradeCode"], props["UpgradeCode"]);
    assert_eq!(later_props["ProductVersion"], "0.1.202");
    assert_ne!(later_code, package_code);
    let later_components = rows(&mut later, "Component");
    let later_component = later_components.iter().find(|row| row[5].as_str() == Some("crewcraft.exe")).unwrap();
    assert_eq!(text(&later_component[1]), component_id);
}

#[test]
fn msi_short_names_are_unique() {
    let mut taken = std::collections::BTreeSet::new();
    assert_eq!(windows_msi::short_long_name("NOTICE.txt", &mut taken).unwrap(), "NOTICE.txt");
    let a = windows_msi::short_long_name("LICENSE-MIT.txt", &mut taken).unwrap();
    let b = windows_msi::short_long_name("LICENSE-APACHE.txt", &mut taken).unwrap();
    assert!(a.ends_with("|LICENSE-MIT.txt") && b.ends_with("|LICENSE-APACHE.txt"));
    let (short_a, short_b) = (a.split('|').next().unwrap(), b.split('|').next().unwrap());
    assert_ne!(short_a.to_ascii_lowercase(), short_b.to_ascii_lowercase());
    for short in [short_a, short_b] {
        let (base, ext) = short.rsplit_once('.').unwrap();
        assert!(base.len() <= 8 && ext.len() <= 3, "{short} is 8.3");
    }
    assert!(windows_msi::short_long_name("a|b", &mut taken).is_err());
}

#[test]
fn ico_holds_png_images() {
    let images = icon::render_sizes(SVG, &icon::ICO_SIZES).unwrap();
    let ico = icon::ico(&images).unwrap();
    assert_eq!(&ico[..4], [0, 0, 1, 0]);
    assert_eq!(u16::from_le_bytes([ico[4], ico[5]]) as usize, icon::ICO_SIZES.len());
    for (at, size) in icon::ICO_SIZES.iter().enumerate() {
        let entry = &ico[6 + 16 * at..6 + 16 * (at + 1)];
        assert_eq!(u32::from(entry[0]), size % 256);
        let len = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(entry[12..16].try_into().unwrap()) as usize;
        assert_eq!(png_size(&ico[offset..offset + len]), (*size, *size));
    }
    assert!(icon::ico(&[(512, images[0].1.clone())]).is_err());
}

// Keeps TreeFile in the public API this task defines.
#[test]
fn tree_files_refuse_unsafe_paths() {
    for bad in ["/etc/passwd", "../x", "a//b", "a/./b", "dir/", ""] {
        assert!(archive::tar(&[TreeFile::new(bad, 0o644, b"x".to_vec())], "./", MTIME).is_err(), "{bad:?} must be refused");
    }
    let clash = [TreeFile::new("a", 0o644, b"x".to_vec()), TreeFile::new("a/b", 0o644, b"y".to_vec())];
    assert!(archive::tar(&clash, "./", MTIME).is_err());
}
