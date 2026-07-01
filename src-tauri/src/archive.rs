use crate::error::{VaultError, VaultResult};
use std::sync::OnceLock;

const ZIP_LOCAL_FILE_HEADER: u32 = 0x0403_4b50;
const ZIP_CENTRAL_DIRECTORY_HEADER: u32 = 0x0201_4b50;
const ZIP_END_OF_CENTRAL_DIRECTORY: u32 = 0x0605_4b50;
const ZIP64_END_OF_CENTRAL_DIRECTORY: u32 = 0x0606_4b50;
const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR: u32 = 0x0706_4b50;
const ZIP64_EXTRA_FIELD_ID: u16 = 0x0001;
const ZIP_STORED_METHOD: u16 = 0;
const DOS_DATE_1980_01_01: u16 = 33;
const U32_MAX_U64: u64 = u32::MAX as u64;

static CRC32_TABLE: OnceLock<[u32; 256]> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct ZipStoredPlan {
    pub local_header: Vec<u8>,
    pub central_directory_and_eocd: Vec<u8>,
    pub payload_size: u64,
}

pub struct Crc32 {
    value: u32,
}

impl Crc32 {
    pub fn new() -> Self {
        Self { value: 0xffff_ffff }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let table = CRC32_TABLE.get_or_init(build_crc32_table);
        for byte in bytes {
            let index = ((self.value ^ u32::from(*byte)) & 0xff) as usize;
            self.value = (self.value >> 8) ^ table[index];
        }
    }

    pub fn finalize(&self) -> u32 {
        !self.value
    }
}

pub fn build_zip_stored_plan(
    file_name: &str,
    original_size: u64,
    crc32: u32,
) -> VaultResult<ZipStoredPlan> {
    let clean_name = sanitize_zip_entry_name(file_name)?;
    let name_bytes = clean_name.as_bytes();
    let name_len = u16::try_from(name_bytes.len())
        .map_err(|_| VaultError::InvalidInput("file name is too long for ZIP".to_string()))?;
    let zip64 = original_size > U32_MAX_U64;
    let local_extra = if zip64 {
        zip64_extra_for_sizes(original_size, original_size)
    } else {
        Vec::new()
    };
    let central_extra = local_extra.clone();
    let local_extra_len = u16::try_from(local_extra.len())
        .map_err(|_| VaultError::InvalidInput("ZIP local extra field is too large".to_string()))?;
    let central_extra_len = u16::try_from(central_extra.len()).map_err(|_| {
        VaultError::InvalidInput("ZIP central extra field is too large".to_string())
    })?;
    let version_needed = if zip64 { 45 } else { 20 };
    let size32 = if zip64 {
        u32::MAX
    } else {
        original_size as u32
    };

    let mut local_header = Vec::with_capacity(30 + name_bytes.len() + local_extra.len());
    push_u32(&mut local_header, ZIP_LOCAL_FILE_HEADER);
    push_u16(&mut local_header, version_needed);
    push_u16(&mut local_header, 0);
    push_u16(&mut local_header, ZIP_STORED_METHOD);
    push_u16(&mut local_header, 0);
    push_u16(&mut local_header, DOS_DATE_1980_01_01);
    push_u32(&mut local_header, crc32);
    push_u32(&mut local_header, size32);
    push_u32(&mut local_header, size32);
    push_u16(&mut local_header, name_len);
    push_u16(&mut local_header, local_extra_len);
    local_header.extend_from_slice(name_bytes);
    local_header.extend_from_slice(&local_extra);

    let central_directory_offset = local_header.len() as u64 + original_size;
    let mut central_directory = Vec::with_capacity(46 + name_bytes.len() + central_extra.len());
    push_u32(&mut central_directory, ZIP_CENTRAL_DIRECTORY_HEADER);
    push_u16(&mut central_directory, version_needed);
    push_u16(&mut central_directory, version_needed);
    push_u16(&mut central_directory, 0);
    push_u16(&mut central_directory, ZIP_STORED_METHOD);
    push_u16(&mut central_directory, 0);
    push_u16(&mut central_directory, DOS_DATE_1980_01_01);
    push_u32(&mut central_directory, crc32);
    push_u32(&mut central_directory, size32);
    push_u32(&mut central_directory, size32);
    push_u16(&mut central_directory, name_len);
    push_u16(&mut central_directory, central_extra_len);
    push_u16(&mut central_directory, 0);
    push_u16(&mut central_directory, 0);
    push_u16(&mut central_directory, 0);
    push_u32(&mut central_directory, 0);
    push_u32(&mut central_directory, 0);
    central_directory.extend_from_slice(name_bytes);
    central_directory.extend_from_slice(&central_extra);

    let central_directory_size = central_directory.len() as u64;
    let mut tail = central_directory;
    let requires_zip64_eocd =
        zip64 || central_directory_offset > U32_MAX_U64 || central_directory_size > U32_MAX_U64;

    if requires_zip64_eocd {
        let zip64_eocd_offset = central_directory_offset + central_directory_size;
        push_u32(&mut tail, ZIP64_END_OF_CENTRAL_DIRECTORY);
        push_u64(&mut tail, 44);
        push_u16(&mut tail, 45);
        push_u16(&mut tail, 45);
        push_u32(&mut tail, 0);
        push_u32(&mut tail, 0);
        push_u64(&mut tail, 1);
        push_u64(&mut tail, 1);
        push_u64(&mut tail, central_directory_size);
        push_u64(&mut tail, central_directory_offset);

        push_u32(&mut tail, ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR);
        push_u32(&mut tail, 0);
        push_u64(&mut tail, zip64_eocd_offset);
        push_u32(&mut tail, 1);
    }

    push_u32(&mut tail, ZIP_END_OF_CENTRAL_DIRECTORY);
    push_u16(&mut tail, 0);
    push_u16(&mut tail, 0);
    push_u16(&mut tail, if requires_zip64_eocd { u16::MAX } else { 1 });
    push_u16(&mut tail, if requires_zip64_eocd { u16::MAX } else { 1 });
    push_u32(
        &mut tail,
        if central_directory_size > U32_MAX_U64 {
            u32::MAX
        } else {
            central_directory_size as u32
        },
    );
    push_u32(
        &mut tail,
        if central_directory_offset > U32_MAX_U64 {
            u32::MAX
        } else {
            central_directory_offset as u32
        },
    );
    push_u16(&mut tail, 0);

    Ok(ZipStoredPlan {
        payload_size: local_header.len() as u64 + original_size + tail.len() as u64,
        local_header,
        central_directory_and_eocd: tail,
    })
}

pub struct ZipStoredDecoder {
    expected_original_size: u64,
    header: Vec<u8>,
    parsed: Option<ZipStoredHeader>,
    remaining: u64,
    crc32: Crc32,
    ignored_after_file_data: u64,
}

impl ZipStoredDecoder {
    pub fn new(expected_original_size: u64) -> Self {
        Self {
            expected_original_size,
            header: Vec::with_capacity(256),
            parsed: None,
            remaining: 0,
            crc32: Crc32::new(),
            ignored_after_file_data: 0,
        }
    }

    pub fn feed(&mut self, input: &[u8]) -> VaultResult<Vec<Vec<u8>>> {
        if self.parsed.is_none() {
            self.header.extend_from_slice(input);
            if let Some(header) = parse_zip_stored_header(&self.header)? {
                if header.uncompressed_size != self.expected_original_size {
                    return Err(VaultError::Integrity(
                        "ZIP payload size does not match encrypted metadata".to_string(),
                    ));
                }
                let remainder = self.header.split_off(header.header_len);
                self.header.clear();
                self.remaining = header.uncompressed_size;
                self.parsed = Some(header);
                return self.consume_data(&remainder);
            }
            return Ok(Vec::new());
        }

        self.consume_data(input)
    }

    pub fn finish(&self) -> VaultResult<()> {
        let header = self.parsed.as_ref().ok_or_else(|| {
            VaultError::Integrity("ZIP payload header was incomplete".to_string())
        })?;
        if self.remaining != 0 {
            return Err(VaultError::Integrity(
                "ZIP payload ended before file data was complete".to_string(),
            ));
        }
        if self.crc32.finalize() != header.crc32 {
            return Err(VaultError::Integrity(
                "ZIP payload CRC32 check failed".to_string(),
            ));
        }
        Ok(())
    }

    fn consume_data(&mut self, input: &[u8]) -> VaultResult<Vec<Vec<u8>>> {
        if self.remaining == 0 {
            self.ignored_after_file_data = self
                .ignored_after_file_data
                .saturating_add(input.len() as u64);
            return Ok(Vec::new());
        }

        let take_len = usize::try_from(self.remaining.min(input.len() as u64))
            .map_err(|_| VaultError::Integrity("ZIP payload length overflow".to_string()))?;
        let data = input[..take_len].to_vec();
        self.crc32.update(&data);
        self.remaining -= take_len as u64;
        if input.len() > take_len {
            self.ignored_after_file_data = self
                .ignored_after_file_data
                .saturating_add((input.len() - take_len) as u64);
        }
        Ok(vec![data])
    }
}

struct ZipStoredHeader {
    header_len: usize,
    uncompressed_size: u64,
    crc32: u32,
}

fn parse_zip_stored_header(bytes: &[u8]) -> VaultResult<Option<ZipStoredHeader>> {
    if bytes.len() < 30 {
        return Ok(None);
    }
    if read_u32(bytes, 0)? != ZIP_LOCAL_FILE_HEADER {
        return Err(VaultError::Integrity(
            "ZIP payload missing local file header".to_string(),
        ));
    }
    let flags = read_u16(bytes, 6)?;
    if flags & 0x0001 != 0 {
        return Err(VaultError::Integrity(
            "ZIP payload must not use ZIP encryption".to_string(),
        ));
    }
    let method = read_u16(bytes, 8)?;
    if method != ZIP_STORED_METHOD {
        return Err(VaultError::Integrity(
            "ZIP payload must use stored method".to_string(),
        ));
    }
    let crc32 = read_u32(bytes, 14)?;
    let compressed_size32 = read_u32(bytes, 18)?;
    let uncompressed_size32 = read_u32(bytes, 22)?;
    let name_len = read_u16(bytes, 26)? as usize;
    let extra_len = read_u16(bytes, 28)? as usize;
    let header_len = 30usize
        .checked_add(name_len)
        .and_then(|value| value.checked_add(extra_len))
        .ok_or_else(|| VaultError::Integrity("ZIP header length overflow".to_string()))?;
    if bytes.len() < header_len {
        return Ok(None);
    }

    let mut compressed_size = u64::from(compressed_size32);
    let mut uncompressed_size = u64::from(uncompressed_size32);
    if compressed_size32 == u32::MAX || uncompressed_size32 == u32::MAX {
        let extra = &bytes[30 + name_len..header_len];
        let (zip64_uncompressed, zip64_compressed) = parse_zip64_sizes(extra)?;
        uncompressed_size = zip64_uncompressed;
        compressed_size = zip64_compressed;
    }
    if compressed_size != uncompressed_size {
        return Err(VaultError::Integrity(
            "ZIP stored payload has mismatched compressed and uncompressed sizes".to_string(),
        ));
    }

    Ok(Some(ZipStoredHeader {
        header_len,
        uncompressed_size,
        crc32,
    }))
}

fn parse_zip64_sizes(extra: &[u8]) -> VaultResult<(u64, u64)> {
    let mut offset = 0usize;
    while offset + 4 <= extra.len() {
        let header_id = read_u16(extra, offset)?;
        let data_size = read_u16(extra, offset + 2)? as usize;
        offset += 4;
        let end = offset
            .checked_add(data_size)
            .ok_or_else(|| VaultError::Integrity("ZIP64 extra length overflow".to_string()))?;
        if end > extra.len() {
            return Err(VaultError::Integrity(
                "ZIP64 extra field exceeds ZIP header".to_string(),
            ));
        }
        if header_id == ZIP64_EXTRA_FIELD_ID {
            if data_size < 16 {
                return Err(VaultError::Integrity(
                    "ZIP64 size extra field is incomplete".to_string(),
                ));
            }
            return Ok((read_u64(extra, offset)?, read_u64(extra, offset + 8)?));
        }
        offset = end;
    }

    Err(VaultError::Integrity(
        "ZIP64 payload sizes were missing".to_string(),
    ))
}

fn zip64_extra_for_sizes(uncompressed_size: u64, compressed_size: u64) -> Vec<u8> {
    let mut extra = Vec::with_capacity(20);
    push_u16(&mut extra, ZIP64_EXTRA_FIELD_ID);
    push_u16(&mut extra, 16);
    push_u64(&mut extra, uncompressed_size);
    push_u64(&mut extra, compressed_size);
    extra
}

fn sanitize_zip_entry_name(file_name: &str) -> VaultResult<String> {
    let name = file_name
        .replace('\\', "_")
        .replace('/', "_")
        .trim()
        .trim_matches('.')
        .to_string();
    if name.is_empty() {
        return Err(VaultError::InvalidInput(
            "ZIP entry file name must not be empty".to_string(),
        ));
    }
    Ok(name)
}

fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (index, slot) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 == 1 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
        }
        *slot = value;
    }
    table
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> VaultResult<u16> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| VaultError::Integrity("short ZIP u16 field".to_string()))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> VaultResult<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| VaultError::Integrity("short ZIP u32 field".to_string()))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> VaultResult<u64> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| VaultError::Integrity("short ZIP u64 field".to_string()))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}
