// SPDX-License-Identifier: MIT OR Apache-2.0
//! The production release a board is burned toward: the public outputs of the one signing
//! (`sign.sh --sign`, the owner's key and passphrase). The signed image, the Non-secure app it holds,
//! that app's digest, and the boot key's hash. Nothing in it is secret; the phone carries it and
//! burns it, and checks it holds together before anything is written.

/// Where flash begins in the RP2350's address map, and where the window it can be loaded into ends.
pub const FLASH_BASE: u32 = 0x1000_0000;
const FLASH_END: u32 = 0x1200_0000;

/// A release that holds together: its image starts at the flash's first byte, the digest is the
/// firmware's own measurement of the Non-secure app (`measurement_ok`: BLAKE3 over the measured
/// window), and the image holds that app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// The signed image as flash holds it from [`FLASH_BASE`].
    pub image: Vec<u8>,
    /// The Non-secure app's digest, burned at Step 5.
    pub digest: [u8; 32],
    /// The boot key's SHA-256, burned at Step 7.
    pub boot_key_hash: [u8; 32],
}

impl Release {
    /// From the signing's outputs: `signed.elf`, `ns_app.bin`, `mu-enrolled.bin` and the boot key's
    /// hash (the 32 bytes `bootkey-otp.json` names `bootkey0`).
    pub fn from_signing(
        signed_elf: &[u8],
        ns_app: &[u8],
        mu_enrolled: &[u8],
        boot_key_hash: &[u8],
    ) -> Result<Self, String> {
        let image = flatten_elf(signed_elf)?;
        let digest: [u8; 32] = mu_enrolled
            .try_into()
            .map_err(|_len| format!("the digest is {} bytes, not 32", mu_enrolled.len()))?;
        let boot_key_hash: [u8; 32] = boot_key_hash.try_into().map_err(|_len| {
            format!(
                "the boot key's hash is {} bytes, not 32",
                boot_key_hash.len()
            )
        })?;
        // The measurement the monitor makes before every authority op, over the same bytes.
        if blake3::hash(ns_app).as_bytes() != &digest {
            return Err(
                "the digest is not the Non-secure app's: a board burned with it would refuse every \
                 authority operation for good"
                    .to_string(),
            );
        }
        if ns_app.is_empty() || !image.windows(ns_app.len()).any(|w| w == ns_app) {
            return Err(
                "the signed image does not hold the Non-secure app the digest is of".to_string(),
            );
        }
        Ok(Self {
            image,
            digest,
            boot_key_hash,
        })
    }
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("the ELF ends before offset {at}"))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("the ELF ends before offset {at}"))
}

const PT_LOAD: u32 = 1;
const EM_ARM: u16 = 40;

/// The flash bytes of a 32-bit little-endian ARM ELF: each loadable segment's file bytes at its
/// physical (load) address, the gaps zero, from the flash's first byte. That is how `objcopy -O
/// binary` lays the image out and how picotool loads it (checked against the yellow board's flash as
/// picotool left it, 2026-11-11). A segment with bytes outside flash cannot be loaded and stops here.
pub fn flatten_elf(elf: &[u8]) -> Result<Vec<u8>, String> {
    if elf.get(0..4) != Some(b"\x7fELF".as_slice()) {
        return Err("not an ELF file".to_string());
    }
    if elf.get(4) != Some(&1) || elf.get(5) != Some(&1) {
        return Err("not a 32-bit little-endian ELF".to_string());
    }
    if u16_at(elf, 18)? != EM_ARM {
        return Err("not an ARM ELF".to_string());
    }
    let phoff = usize::try_from(u32_at(elf, 28)?).map_err(|e| e.to_string())?;
    let phentsize = usize::from(u16_at(elf, 42)?);
    let phnum = usize::from(u16_at(elf, 44)?);
    let mut segments = Vec::new();
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let filesz = u32_at(elf, ph + 16)?;
        if u32_at(elf, ph)? != PT_LOAD || filesz == 0 {
            continue;
        }
        let offset = usize::try_from(u32_at(elf, ph + 4)?).map_err(|e| e.to_string())?;
        let paddr = u32_at(elf, ph + 12)?;
        let end = paddr
            .checked_add(filesz)
            .ok_or("a segment runs past the address space")?;
        if paddr < FLASH_BASE || end > FLASH_END {
            return Err(format!(
                "a segment loads at {paddr:#010x}..{end:#010x}, outside flash: it cannot be loaded"
            ));
        }
        let len = usize::try_from(filesz).map_err(|e| e.to_string())?;
        let bytes = elf
            .get(offset..offset + len)
            .ok_or("a segment runs past the end of the ELF")?;
        segments.push((paddr, bytes));
    }
    let first = segments
        .iter()
        .map(|(addr, _)| *addr)
        .min()
        .ok_or("the ELF loads nothing into flash")?;
    if first != FLASH_BASE {
        return Err(format!(
            "the image starts at {first:#010x}, not at the flash's first byte"
        ));
    }
    let end = segments
        .iter()
        .map(|(addr, bytes)| *addr as usize + bytes.len())
        .max()
        .ok_or("the ELF loads nothing into flash")?;
    let mut image = vec![0u8; end - FLASH_BASE as usize];
    for (addr, bytes) in segments {
        let at = (addr - FLASH_BASE) as usize;
        image[at..at + bytes.len()].copy_from_slice(bytes);
    }
    Ok(image)
}
