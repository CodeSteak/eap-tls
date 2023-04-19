#[cfg(test)]
pub fn hex_to_vec(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|chunk| u8::from_str_radix(chunk, 16).unwrap())
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedSlice<const N: usize> {
    Inline {
        buffer: [u8; N],
        len: u8,
    },
    #[cfg(any(feature = "std", feature = "alloc"))]
    Heap(Vec<u8>),
}

impl<const N: usize> OwnedSlice<N> {
    pub fn from(value: &[u8]) -> Self {
        Self::try_from(value).expect("Cannot allocate up to N bytes on no_std")
    }

    pub fn new() -> Self {
        Self::from(&[])
    }
}

impl<const N: usize> TryFrom<&[u8]> for OwnedSlice<N> {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        assert!(N <= u8::MAX as usize);

        if value.len() <= N {
            let mut buffer = [0; N];
            buffer[..value.len()].copy_from_slice(value);
            Ok(Self::Inline {
                buffer,
                len: value.len() as u8,
            })
        } else {
            #[cfg(any(feature = "std", feature = "alloc"))]
            {
                Ok(Self::Heap(value.to_vec()))
            }
            #[cfg(not(any(feature = "std", feature = "alloc")))]
            {
                Err(())
            }
        }
    }
}

impl<const N: usize> AsRef<[u8]> for OwnedSlice<N> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Inline { buffer, len } => &buffer[..*len as usize],
            #[cfg(feature = "std")]
            Self::Heap(buffer) => buffer,
        }
    }
}
