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

impl<const N: usize> From<&[u8]> for OwnedSlice<N> {
    fn from(value: &[u8]) -> Self {
        assert!(N <= u8::MAX as usize);

        if value.len() <= N {
            let mut buffer = [0; N];
            buffer[..value.len()].copy_from_slice(value);
            Self::Inline {
                buffer,
                len: value.len() as u8,
            }
        } else {
            #[cfg(any(feature = "std", feature = "alloc"))]
            {
                Self::Heap(value.to_vec())
            }
            #[cfg(not(any(feature = "std", feature = "alloc")))]
            {
                panic!("Cannot allocate up to {} bytes on no_std", value.len());
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
