/// File utilities  
///
///  Contains helper functions for file operations, such as reading and writing files.
///
/// # Example
///
/// ```rust
/// use dsm::utils::file::{read_file, write_file};
/// # std::fs::write("test.txt", "Hello from doc test!").unwrap();
/// let data = read_file("test.txt").unwrap();
///
/// // Example of writing data to a file
/// write_file("output.txt", &data).unwrap();
///  ```
///
use std::fs::File;
use std::io::{self, Read, Write};
/// Reads the contents of a file and returns it as a `Vec<u8>`.
pub fn read_file(path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}
/// Writes data to a file.
pub fn write_file(path: &str, data: &[u8]) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    // Helper function to generate a temporary file path
    fn temp_file_path(name: &str) -> String {
        // Ensure the target directory exists
        let target_dir = "target";
        if !Path::new(target_dir).exists() {
            let _ = std::fs::create_dir_all(target_dir);
        }
        format!("target/tmp_test_{}", name)
    }

    // Clean up temporary files after tests
    fn cleanup_temp_file(path: &str) {
        if Path::new(path).exists() {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn test_write_and_read_file() {
        let test_data = b"Hello, file utilities test!";
        let path = temp_file_path("write_read.txt");

        // Clean up any existing file from previous test runs
        cleanup_temp_file(&path);

        // Write data to file
        let write_result = write_file(&path, test_data);
        assert!(write_result.is_ok());

        // Read data from file
        let read_result = read_file(&path);
        assert!(read_result.is_ok());

        let read_data = read_result.unwrap();
        assert_eq!(read_data, test_data);

        // Clean up
        cleanup_temp_file(&path);
    }

    #[test]
    fn test_read_nonexistent_file() {
        let path = temp_file_path("nonexistent.txt");

        // Ensure the file doesn't exist
        cleanup_temp_file(&path);

        // Try to read a non-existent file
        let result = read_file(&path);
        assert!(result.is_err());

        // Verify it's the expected error kind
        match result {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            Ok(_) => panic!("Expected an error"),
        }
    }

    #[test]
    fn test_write_to_invalid_path() {
        // Try to write to an invalid path (directory that doesn't exist)
        let result = write_file("/nonexistent_dir/test.txt", b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_file() {
        let path = temp_file_path("empty.txt");

        // Clean up any existing file
        cleanup_temp_file(&path);

        // Write empty data
        let write_result = write_file(&path, b"");
        assert!(write_result.is_ok());

        // Read the empty file
        let read_result = read_file(&path);
        assert!(read_result.is_ok());
        assert_eq!(read_result.unwrap(), b"");

        // Clean up
        cleanup_temp_file(&path);
    }

    #[test]
    fn test_large_file() {
        let path = temp_file_path("large.txt");

        // Clean up any existing file
        cleanup_temp_file(&path);

        // Create a 1MB data buffer
        let data = vec![42u8; 1024 * 1024];

        // Write large data
        let write_result = write_file(&path, &data);
        assert!(write_result.is_ok());

        // Read large data
        let read_result = read_file(&path);
        assert!(read_result.is_ok());
        assert_eq!(read_result.unwrap(), data);

        // Clean up
        cleanup_temp_file(&path);
    }
}
