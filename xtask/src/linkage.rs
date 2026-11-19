//! What a built binary needs from the machine it runs on, read from the binary itself.
//!
//! Linux: the shared libraries an ELF file links (`DT_NEEDED`) and the symbol versions it requires from them, which
//! become the `.deb` `Depends:` line. A library without a mapping here fails the build, so a new link is never
//! shipped with a silently wrong `Depends:`.
//!
//! Windows: the DLLs a PE file imports. The packages ship one `.exe` with nothing beside it, so an import of a
//! MinGW runtime DLL (which Windows does not have) fails the build.

use object::read::elf::{Dyn, FileHeader};
use object::{Architecture, BinaryFormat, Object, elf};

use crate::{Error, Result};

/// The libraries an ELF binary links and the versions it requires, as `(library, version)` pairs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ElfLinks {
    pub needed: Vec<String>,
    pub versions: Vec<(String, String)>,
}

fn text(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::new("a library or version name in the binary is not UTF-8"))
}

fn elf_error(error: object::Error) -> Error {
    Error::new(format!("reading the ELF binary: {error}"))
}

/// Reads `DT_NEEDED` and the GNU version requirements of a 64-bit x86-64 ELF file.
pub fn elf_links(data: &[u8]) -> Result<ElfLinks> {
    let file = object::File::parse(data).map_err(elf_error)?;
    if file.format() != BinaryFormat::Elf || file.architecture() != Architecture::X86_64 {
        return Err(Error::new(format!("expected an x86-64 ELF binary, found {:?} {:?}", file.format(), file.architecture())));
    }
    let header = elf::FileHeader64::<object::Endianness>::parse(data).map_err(elf_error)?;
    let endian = header.endian().map_err(elf_error)?;
    let sections = header.sections(endian, data).map_err(elf_error)?;
    let mut links = ElfLinks::default();
    if let Some((dynamic, link)) = sections.dynamic(endian, data).map_err(elf_error)? {
        let strings = sections.strings(endian, data, link).map_err(elf_error)?;
        for entry in dynamic {
            if entry.tag32(endian) == Some(elf::DT_NEEDED) {
                links.needed.push(text(entry.string(endian, strings).map_err(elf_error)?)?);
            }
        }
    }
    if let Some((mut needs, link)) = sections.gnu_verneed(endian, data).map_err(elf_error)? {
        let strings = sections.strings(endian, data, link).map_err(elf_error)?;
        while let Some((need, mut auxes)) = needs.next().map_err(elf_error)? {
            let library = text(need.file(endian, strings).map_err(elf_error)?)?;
            while let Some(aux) = auxes.next().map_err(elf_error)? {
                links.versions.push((library.clone(), text(aux.name(endian, strings).map_err(elf_error)?)?));
            }
        }
    }
    Ok(links)
}

/// A Debian package that provides some libraries, and the prefix of their symbol version names.
struct Provider {
    package: &'static str,
    libraries: &'static [&'static str],
    version_prefix: &'static str,
}

const PROVIDERS: [Provider; 2] = [
    Provider {
        package: "libc6",
        libraries: &["libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0", "librt.so.1", "libutil.so.1", "ld-linux-x86-64.so.2"],
        version_prefix: "GLIBC_",
    },
    Provider { package: "libgcc-s1", libraries: &["libgcc_s.so.1"], version_prefix: "GCC_" },
];

fn numbers(version: &str) -> Option<Vec<u32>> {
    version.split('.').map(|part| part.parse::<u32>().ok()).collect()
}

/// The `Depends:` entries for what an ELF binary links: one per providing package, with the highest symbol
/// version it requires (`libc6 (>= 2.34)`). Fails on a library or version this table does not know.
pub fn debian_depends(links: &ElfLinks) -> Result<Vec<String>> {
    for library in &links.needed {
        if !PROVIDERS.iter().any(|provider| provider.libraries.contains(&library.as_str())) {
            return Err(Error::new(format!(
                "the binary links {library}, which has no Debian package in xtask/src/linkage.rs; add the package that provides it"
            )));
        }
    }
    let mut depends = Vec::new();
    for provider in &PROVIDERS {
        if !links.needed.iter().any(|library| provider.libraries.contains(&library.as_str())) {
            continue;
        }
        let mut highest: Option<(Vec<u32>, String)> = None;
        for (library, version) in &links.versions {
            if !provider.libraries.contains(&library.as_str()) {
                continue;
            }
            let plain = version.strip_prefix(provider.version_prefix).and_then(|v| numbers(v).map(|n| (n, v.to_string())));
            let Some((key, plain)) = plain else {
                return Err(Error::new(format!("the binary requires {library} version {version}, which xtask cannot turn into a Depends: entry")));
            };
            if highest.as_ref().is_none_or(|(best, _)| key > *best) {
                highest = Some((key, plain));
            }
        }
        depends.push(match highest {
            Some((_, version)) => format!("{} (>= {version})", provider.package),
            None => provider.package.to_string(),
        });
    }
    Ok(depends)
}

/// The DLLs a 64-bit x86-64 PE file imports, lowercase, sorted, each once.
pub fn pe_imports(data: &[u8]) -> Result<Vec<String>> {
    let file = object::File::parse(data).map_err(|error| Error::new(format!("reading the Windows binary: {error}")))?;
    if file.format() != BinaryFormat::Pe || file.architecture() != Architecture::X86_64 || !file.is_64() {
        return Err(Error::new(format!("expected an x86-64 PE32+ binary, found {:?} {:?}", file.format(), file.architecture())));
    }
    let imports = file.imports().map_err(|error| Error::new(format!("reading the Windows binary's imports: {error}")))?;
    let mut dlls: Vec<String> = Vec::new();
    for import in imports {
        dlls.push(text(import.library())?.to_ascii_lowercase());
    }
    dlls.sort();
    dlls.dedup();
    Ok(dlls)
}

/// Fails when a Windows binary imports a DLL that Windows does not ship, such as the MinGW runtime
/// (`libgcc_s_seh-1.dll`, `libwinpthread-1.dll`).
pub fn check_windows_imports(dlls: &[String]) -> Result<()> {
    match dlls.iter().find(|dll| dll.starts_with("lib")) {
        Some(dll) => Err(Error::new(format!("the Windows binary imports {dll}, which Windows does not have; link it statically"))),
        None => Ok(()),
    }
}

/// Fails unless `data` is a 64-bit Mach-O binary for the architecture of the Rust target `triple`
/// (`x86_64-apple-darwin` or `aarch64-apple-darwin`), checked before the two builds are joined. Only the header is read
/// (magic `MH_MAGIC_64`, then the CPU type): a full parse refused real linker output ("Invalid Mach-O number of
/// sections") although `file` and `otool` read it fine, and the header is all this check needs.
pub fn check_macho(data: &[u8], triple: &str) -> Result<()> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    let (want, name) = if triple.starts_with("aarch64") { (CPU_TYPE_ARM64, "arm64") } else { (CPU_TYPE_X86_64, "x86_64") };
    let word = |at: usize| data.get(at..at + 4).and_then(|bytes| bytes.try_into().ok()).map(u32::from_le_bytes);
    match (word(0), word(4)) {
        (Some(MH_MAGIC_64), Some(cpu)) if cpu == want => Ok(()),
        (Some(MH_MAGIC_64), Some(cpu)) => Err(Error::new(format!("expected an {name} Mach-O binary for {triple}, found CPU type {cpu:#x}"))),
        _ => Err(Error::new(format!("expected a 64-bit Mach-O binary for {triple}"))),
    }
}
