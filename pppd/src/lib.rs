
#[allow(dead_code, non_camel_case_types, non_snake_case, non_upper_case_globals, improper_ctypes, clippy::all)]
mod bindings;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
