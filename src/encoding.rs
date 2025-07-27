use std::{
    io::{self, Read, Write},
    vec,
};
use strum::FromRepr;

fn read_len<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut buffer = [0u8; 2];
    reader.read_exact(&mut buffer)?;
    Ok(u16::from_be_bytes(buffer))
}

fn write_len<W: Write>(writer: &mut W, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

fn read_field(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    // TODO: is a shared buffer here worth it? Is the compiler smart enough to optimize?

    let len = read_len(reader)?;
    let mut buf = vec![0u8; len as usize];

    reader.read_exact(&mut buf).map(|_| buf)
}

fn err_invalid_field(field: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Invalid field: {field}"),
    )
}

macro_rules! read_field_into {
    ($reader:ident, $field:literal) => {
        read_field($reader)?
            .try_into()
            .map_err(|_| err_invalid_field($field))
    };
}

fn write_field(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    let prefix = bytes.len() as u16;

    write_len(writer, prefix)?;
    writer.write_all(bytes)?;

    Ok(())
}

// Public API

#[repr(u16)]
#[derive(Debug, FromRepr, Clone)]
pub enum Family {
    Local = 256,
    Wild = 65535,

    Netname = 254,
    Krb5Principal = 253,
    LocalHost = 252,
    ProbablyWildNonspec = 0, // TODO:
}

#[derive(Debug)]
pub struct Entry {
    pub family: Family,
    pub address: Vec<u8>,
    pub display_number: String,
    pub auth_name: String,
    pub auth_data: Vec<u8>,
}

impl Entry {
    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Option<Self>> {
        let family = match read_len(reader) {
            Ok(value) => value,
            Err(_) => return Ok(None), // TODO: replace _ with EOF
        };
        let family = Family::from_repr(family).ok_or(err_invalid_field("family"));

        Ok(Some(Self {
            family: family?,
            address: read_field_into!(reader, "address")?,
            display_number: read_field_into!(reader, "display_number")?,
            auth_name: read_field_into!(reader, "auth_name")?,
            auth_data: read_field_into!(reader, "auth_data")?,
        }))
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        write_len(writer, self.family.clone() as u16)?;
        write_field(writer, &self.address)?;
        write_field(writer, self.display_number.as_bytes())?;
        write_field(writer, self.auth_name.as_bytes())?;
        write_field(writer, &self.auth_data)?;

        Ok(())
    }
}

pub struct XAuthority(Vec<Entry>);

impl XAuthority {
    pub fn new(entries: Option<Vec<Entry>>) -> Self {
        Self(entries.unwrap_or_default())
    }

    pub fn add_entry(&mut self, entry: Entry) {
        self.0.push(entry);
    }

    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = Vec::new();

        while let Some(entry) = Entry::read_from(reader)? {
            buf.push(entry);
        }

        Ok(Self(buf))
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        for entry in &self.0 {
            entry.write_to(writer)?
        }

        Ok(())
    }
}

impl IntoIterator for XAuthority {
    type Item = Entry;
    type IntoIter = vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
