//! Code coverage from a tracer, mapped to the sample's functions (from REA): the strongest
//! signal that a fake answer made the sample do something new.
//!
//! - drcov (DynamoRIO's `drrun -t drcov`, and the Frida/Lighthouse tools that emit the
//!   same format): a module table, then a binary table of basic blocks (module-relative).
//! - JSON lines, for any tracer that can stream: `{"pid": 1234, "functions": ["name", ...]}`
//!   or `{"pid": 1234, "addresses": ["0x401020", ...]}` (virtual addresses), optionally
//!   with `"time"`: when the code ran (Unix milliseconds), for exact attribution.

use std::collections::BTreeSet;

use anyhow::{bail, Context};
use serde::Deserialize;

use crate::hints::Function;

#[derive(Debug, Clone, PartialEq)]
pub struct Module {
    pub id: u16,
    pub base: u64,
    pub end: u64,
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Drcov {
    pub modules: Vec<Module>,
    /// (module id, offset from the module's base)
    pub blocks: Vec<(u16, u32)>,
    /// From the file name drcov uses ("drcov.<app>.<pid>.<n>.proc.log"), if present
    pub pid: Option<u32>,
}

impl Drcov {
    pub fn parse(data: &[u8], file_name: &str) -> anyhow::Result<Drcov> {
        let mut lines = LineReader { data, at: 0 };
        let version = lines.next().context("empty drcov file")?;
        if !version.starts_with("DRCOV VERSION:") {
            bail!("not a drcov file");
        }
        let mut header = lines.next().context("truncated drcov header")?;
        if header.starts_with("DRCOV FLAVOR:") {
            header = lines.next().context("truncated drcov header")?;
        }
        // "Module Table: version 2, count 3" or (v1) "Module Table: 3"
        let count: usize = header.rsplit([' ', ',']).next().and_then(|n| n.trim().parse().ok()).context("bad module table header")?;
        let columns_line = lines.next().context("truncated module table")?;
        let columns: Vec<String> = columns_line.trim_start_matches("Columns:").split(',').map(|c| c.trim().to_ascii_lowercase()).collect();
        let column = |names: &[&str]| columns.iter().position(|c| names.contains(&c.as_str()));
        let (id_col, base_col, end_col, path_col) = (column(&["id"]), column(&["base", "start"]), column(&["end"]), column(&["path"]));
        let mut modules = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let line = lines.next().context("truncated module table")?;
            let fields: Vec<&str> = line.splitn(columns.len(), ',').map(str::trim).collect();
            let get = |index: Option<usize>| index.and_then(|i| fields.get(i)).copied().unwrap_or("");
            let hex = |text: &str| u64::from_str_radix(text.trim_start_matches("0x"), 16).unwrap_or(0);
            modules.push(Module {
                id: get(id_col).parse().unwrap_or(modules.len() as u16),
                base: hex(get(base_col)),
                end: hex(get(end_col)),
                path: get(path_col).to_string(),
            });
        }
        let bb_header = lines.next().context("missing BB table")?;
        let count: usize = bb_header.trim_start_matches("BB Table:").split_whitespace().next().and_then(|n| n.parse().ok()).context("bad BB table header")?;
        let table = &data[lines.at..];
        if table.len() < count.saturating_mul(8) {
            bail!("truncated BB table ({count} blocks announced)");
        }
        let blocks = table.chunks_exact(8).take(count).map(|b| (u16::from_le_bytes([b[6], b[7]]), u32::from_le_bytes([b[0], b[1], b[2], b[3]]))).collect();
        let pid = file_name.split('.').find_map(|part| part.parse::<u32>().ok().filter(|p| *p > 1));
        Ok(Drcov { modules, blocks, pid })
    }

    /// Virtual addresses of the blocks in the module whose path ends with `module`
    /// (case-insensitive), rebased onto `image_base` (the address REA's functions use)
    pub fn addresses(&self, module: &str, image_base: u64) -> Vec<u64> {
        let module = module.to_ascii_lowercase();
        let ids: BTreeSet<u16> = self
            .modules
            .iter()
            .filter(|m| m.path.to_ascii_lowercase().replace('\\', "/").rsplit('/').next().is_some_and(|name| name == module))
            .map(|m| m.id)
            .collect();
        self.blocks.iter().filter(|(id, _)| ids.contains(id)).map(|(_, offset)| image_base + u64::from(*offset)).collect()
    }
}

struct LineReader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> LineReader<'a> {
    fn next(&mut self) -> Option<String> {
        let rest = self.data.get(self.at..)?;
        let end = rest.iter().position(|&b| b == b'\n')?;
        self.at += end + 1;
        Some(String::from_utf8_lossy(&rest[..end]).trim_end_matches('\r').to_string())
    }
}

/// One JSON-lines coverage record
#[derive(Debug, Clone, Deserialize)]
pub struct CoverageEvent {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub functions: Vec<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
    /// When the code ran (Unix milliseconds): credit goes to the answers just before it
    #[serde(default)]
    pub time: Option<f64>,
}

/// Address -> function, for the sample's known functions
#[derive(Debug, Clone, Default)]
pub struct FunctionMap {
    /// Sorted by address; each covers up to its size, or up to the next function
    functions: Vec<Function>,
}

impl FunctionMap {
    pub fn new(mut functions: Vec<Function>) -> FunctionMap {
        functions.sort_by_key(|f| f.address);
        functions.dedup_by_key(|f| f.address);
        FunctionMap { functions }
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.functions.iter().map(|f| f.name.as_str())
    }

    /// The function containing `address`, if any
    pub fn function_at(&self, address: u64) -> Option<&str> {
        let index = self.functions.partition_point(|f| f.address <= address).checked_sub(1)?;
        let function = &self.functions[index];
        let end = match function.size {
            Some(size) => function.address + size,
            None => self.functions.get(index + 1).map(|next| next.address).unwrap_or(u64::MAX),
        };
        (address < end).then_some(function.name.as_str())
    }

    pub fn functions_for(&self, addresses: impl IntoIterator<Item = u64>) -> BTreeSet<String> {
        addresses.into_iter().filter_map(|a| self.function_at(a).map(str::to_string)).collect()
    }
}

pub fn parse_hex(text: &str) -> Option<u64> {
    let text = text.trim();
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A drcov v2 file, as DynamoRIO writes it
    pub fn drcov(blocks: &[(u16, u32)]) -> Vec<u8> {
        let mut file = b"DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\nModule Table: version 2, count 2\n\
Columns: id, base, end, entry, checksum, timestamp, path\n\
 0, 0x00007ff600000000, 0x00007ff600020000, 0x0000000000000000, 0x00000000, 0x00000000, C:\\samples\\bot.exe\n\
 1, 0x00007ffb10000000, 0x00007ffb10100000, 0x0000000000000000, 0x00000000, 0x00000000, C:\\Windows\\System32\\ntdll.dll\n"
            .to_vec();
        file.extend(format!("BB Table: {} bbs\n", blocks.len()).as_bytes());
        for (module, offset) in blocks {
            file.extend(offset.to_le_bytes());
            file.extend(16u16.to_le_bytes());
            file.extend(module.to_le_bytes());
        }
        file
    }

    #[test]
    fn parses_drcov_and_maps_blocks_to_functions() {
        let data = drcov(&[(0, 0x1000), (0, 0x1210), (1, 0x5000), (0, 0x9999)]);
        let coverage = Drcov::parse(&data, "drcov.bot.exe.4242.0000.proc.log").unwrap();
        assert_eq!(coverage.modules.len(), 2);
        assert_eq!(coverage.pid, Some(4242));
        let addresses = coverage.addresses("bot.exe", 0x400000);
        assert_eq!(addresses, [0x401000, 0x401210, 0x409999]);
        let map = FunctionMap::new(vec![
            Function { address: 0x401000, name: "start".into(), size: Some(0x100) },
            Function { address: 0x401200, name: "cmd_download".into(), size: None },
            Function { address: 0x402000, name: "cmd_keylog".into(), size: Some(0x10) },
        ]);
        let hit = map.functions_for(addresses);
        assert_eq!(hit.into_iter().collect::<Vec<_>>(), ["cmd_download", "start"]); // 0x409999 is past cmd_keylog
        assert_eq!(map.function_at(0x401100), None); // Past start's size
        assert!(Drcov::parse(b"garbage\n", "x").is_err());
        assert!(Drcov::parse(&data[..data.len() - 3], "x").is_err()); // Truncated table
    }
}
