use std::{
    io::{self, Read, Write},
    vec,
};

fn read_len<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut buffer = [0u8; 2];
    reader.read_exact(&mut buffer)?;
    Ok(u16::from_be_bytes(buffer))
}

fn write_len<W: Write>(writer: &mut W, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

fn read_field<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    // TODO: is a shared buffer for length here worth it?
    // Is the compiler smart enough to optimize?

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

#[derive(Debug)]
pub enum Family {
    Local,
    Wild,
    Other(u16),
    // Netname, 254
    // Krb5Principal, 253
    // LocalHost, 252
}

impl Family {
    fn encode(&self) -> u16 {
        match self {
            Self::Local => 256,
            Self::Wild => 65535, // TODO:
            Self::Other(x) => *x,
        }
    }

    fn decode(value: u16) -> Self {
        match value {
            256 => Self::Local,
            65535 => Self::Wild,
            x => Self::Other(x),
        }
    }
}

#[derive(Debug)]
pub struct XAuthorityEntry {
    pub family: Family,
    pub address: Vec<u8>,
    pub display_number: String,
    pub auth_name: String,
    pub auth_data: Vec<u8>,
}

impl XAuthorityEntry {
    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Option<Self>> {
        let family = Family::decode(match read_len(reader) {
            Ok(value) => value,
            Err(e) => {
                return match e.kind() {
                    io::ErrorKind::UnexpectedEof => Ok(None),
                    _ => Err(e),
                };
            }
        });

        Ok(Some(Self {
            family,
            address: read_field_into!(reader, "address")?,
            display_number: read_field_into!(reader, "display_number")?,
            auth_name: read_field_into!(reader, "auth_name")?,
            auth_data: read_field_into!(reader, "auth_data")?,
        }))
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        write_len(writer, self.family.encode())?;
        write_field(writer, &self.address)?;
        write_field(writer, self.display_number.as_bytes())?;
        write_field(writer, self.auth_name.as_bytes())?;
        write_field(writer, &self.auth_data)?;

        Ok(())
    }
}
