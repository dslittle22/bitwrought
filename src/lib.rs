use clap::{Arg, ArgAction, Command};
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::UNIX_EPOCH;
use xattr::SUPPORTED_PLATFORM;

const BUFFER_SIZE: usize = 8;
const HASH_XATTR: &str = "com.bitwrought.hash";
const MODIFIED_XATTR: &str = "com.bitwrought.modified";

pub fn run() -> Result<(), Box<dyn Error>> {
    if !SUPPORTED_PLATFORM {
        print!("Sorry, your platform is not supported.");
        exit(1);
    }

    let clap = clap_setup();
    let args = env::args();
    let (paths, recursive, delete, verbose) = parse_args(clap, args);

    let mut all_files: Vec<PathBuf> = Vec::new();

    for path in paths {
        let path_metadata = fs::metadata(&path);
        if path_metadata.is_err() {
            all_files.push(path);
            continue;
        }
        if path_metadata.unwrap().is_dir() {
            let mut files = traverse_dir(&path, recursive).unwrap();
            all_files.append(&mut files);
        } else {
            all_files.push(path);
        }
    }

    if verbose {
        let all_filenames_str = all_files
            .iter()
            .map(|val| format!("{:?}", val.as_os_str()))
            .collect::<Vec<String>>()
            .join(", ");
        let action = if delete {
            "delete hash and modified timestamp xattrs from"
        } else {
            "check hashes for"
        };
        println!(
            "All file paths collected: {all_filenames_str}.\nAttempting to {action} all files."
        );
    }

    if all_files.len() > 10 {
        many_files_warning(all_files.len());
    }

    let mut result_strings: Vec<String> = Vec::new();

    for file in all_files {
        let status = if delete {
            delete_xattrs(&file)
        } else {
            check(&file, verbose)
        };
        result_strings.push(format!("File \"{}\": {}", &file.to_str().unwrap(), status));
    }

    if verbose {
        println!();
    }

    for s in result_strings {
        println!("{s}");
    }

    fn many_files_warning(num_files: usize) {
        println!(
            "Warning: bitwrought is about to check or write hashes for {num_files} files.\nType \"Yes\" to continue, or press any key to abort."
        );
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();

        if !&line.eq("Yes\n") {
            exit(0);
        }
    }
    Ok(())
}

enum FileStatus {
    DoesNotExist,
    BadPermissions,
    Modified,
    Rotten,
    Ok(String),
}

impl Display for FileStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPermissions => write!(f, "❗️ Bad file permissions."),
            Self::DoesNotExist => write!(f, "❗️ File does not exist."),
            Self::Modified => write!(f, "❕ File hashes do not match, but it looks like the file was modified. Recalculating hash and timestamp for modified file."),
            Self::Rotten => write!(f, "❗️ File hashes do not match, but it does NOT look like the file was modified. The file may be corrupt."),
            Self::Ok(s) => write!(f, "✅ {}", s),
        }
    }
}

fn check(path: &Path, verbose: bool) -> FileStatus {
    let file = PathBuf::from(path);
    let metadata = match fs::metadata(&file) {
        Ok(metadata) => metadata,
        Err(_) => return FileStatus::DoesNotExist,
    };

    if metadata.permissions().readonly() {
        return FileStatus::BadPermissions;
    }

    let saved_hash = xattr::get(file, HASH_XATTR).unwrap().unwrap_or_default();
    let saved_hash = std::str::from_utf8(&saved_hash).unwrap();
    if saved_hash.is_empty() {
        save_file_hash(path).unwrap();
        FileStatus::Ok(String::from(
            "File has no hash saved. Calculating and storing now.",
        ))
    } else {
        let mut file = fs::File::open(path).unwrap();
        let hash = calculate_file_digest_buffered(&mut file).unwrap();
        if verbose {
            let path_str = path.display();
            println!("File \"{path_str}\" hash previously saved: {saved_hash}");
            println!("File \"{path_str}\" newly calculated hash: {hash}");
        }

        if saved_hash == hash {
            FileStatus::Ok(String::from("File hash matches previously saved result."))
        } else {
            let saved_timestamp = xattr::get(path, MODIFIED_XATTR)
                .unwrap()
                .unwrap_or_default();
            let saved_timestamp = String::from_utf8(saved_timestamp).unwrap();
            let metadata = fs::metadata(path).unwrap();
            let last_modified = metadata
                .modified()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string();

            if verbose {
                let path_str = path.display();
                println!("Modified timestamp for file \"{path_str}\" previously saved in bitwrought: {saved_timestamp}");
                println!("Modified timestamp from file \"{path_str}\" metadata: {last_modified}");
            }

            if last_modified > saved_timestamp {
                // xattr::set(path, MODIFIED_XATTR, last_modified.as_bytes()).unwrap();
                save_file_hash(path).unwrap();
                FileStatus::Modified
            } else {
                FileStatus::Rotten
            }
        }
    }
}

fn delete_xattrs(path: &Path) -> FileStatus {
    let file = PathBuf::from(path);
    let metadata = match fs::metadata(file) {
        Ok(metadata) => metadata,
        Err(_) => return FileStatus::DoesNotExist,
    };

    if metadata.permissions().readonly() {
        return FileStatus::BadPermissions;
    }
    let hash_result = xattr::remove(path, HASH_XATTR);
    let mod_result = xattr::remove(path, MODIFIED_XATTR);
    if hash_result.is_err() || mod_result.is_err() {
        FileStatus::Ok(String::from(
            "Hash and timestamp successfully removed, although some xattrs were not present.",
        ))
    } else {
        FileStatus::Ok(String::from(
            "Hash and timestamp xattrs successfully removed.",
        ))
    }
}

// modify file modified time: `touch -t 202301010000 fizz`

fn clap_setup() -> Command {
    Command::new("bitwrought")
        .version("0.1")
        .author("Danny Little")
        .about("Detects changes in files and notifies of these changes when run.")
        .after_help(
            "Bitwrought will look at each file passed to it, and checks if it has a hash saved.
If it does, it recalculates the file's hash and compares it to the saved one.
If not, it calculates a new one and saves it to the file in a custom xattr.
If passed a directory, bitwrought will check each file with a shallow traversal:
it does not check directories within the directory passed unless the --recursive option is used.",
        )
        .arg(
            Arg::new("path")
                .action(ArgAction::Append)
                .required(true)
                .help("One or more files or directories"),
        )
        .arg(
            Arg::new("recursive")
                .short('r')
                .long("recursive")
                .action(ArgAction::SetTrue)
                .help("Check all files in the directory recursively"),
        )
        .arg(
            Arg::new("delete")
                .short('d')
                .long("delete")
                .action(ArgAction::SetTrue)
                .help("Delete hashes saved by bitwrought"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue),
        )
}

fn parse_args<I, T>(clap: Command, args: I) -> (Vec<PathBuf>, bool, bool, bool)
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = clap.get_matches_from(args);

    let paths = matches
        .get_many::<String>("path")
        .unwrap_or_default()
        .map(PathBuf::from)
        .collect();

    let recursive = matches.get_flag("recursive");
    let delete = matches.get_flag("delete");
    let verbose = matches.get_flag("verbose");

    (paths, recursive, delete, verbose)
}

fn calculate_file_digest_buffered<T: Read + Seek>(file: &mut T) -> Result<String, Box<dyn Error>> {
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut hasher = Sha256::new();

    let mut bytes_read = 1;
    while bytes_read > 0 {
        bytes_read = file.read(&mut buffer)?;
        hasher.update(&buffer[..bytes_read]);
    }
    let digest = hasher.finalize();
    Ok(format!("{:x}", digest))
}

fn save_file_hash(path: &Path) -> Result<(), Box<dyn Error>> {
    let mut file = fs::File::open(path).unwrap();
    let hash = calculate_file_digest_buffered(&mut file).unwrap();
    xattr::set(path, HASH_XATTR, hash.as_bytes()).unwrap();
    let time = xattr::get(path, MODIFIED_XATTR).unwrap();
    if time.is_none() {
        let metadata = fs::metadata(path).unwrap();
        let last_modified = metadata
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        xattr::set(path, MODIFIED_XATTR, last_modified.as_bytes()).unwrap();
    }
    Ok(())
}

fn traverse_dir(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut all_files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() && recursive {
            let mut dir_files = traverse_dir(&path, true).unwrap();
            all_files.append(&mut dir_files);
        } else if !path.is_dir() && !should_ignore(&path) {
            all_files.push(entry.path());
        }
    }
    Ok(all_files)
}

fn should_ignore(path: &Path) -> bool {
    path.ends_with(".DS_Store")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use std::fs;
    use std::io::{BufRead, BufReader, BufWriter, Write};
    use std::path::Path;
    use tempfile::{tempfile, NamedTempFile};

    //1. test that arguments are parsed correctly (this will be a couple of tests)
    #[test]
    fn valid_command_lines_ok() {
        let valid_lines = [
            "bitwrought test1 test2",
            "bitwrought a/b/c",
            "bitwrought test -rdv",
            "bitwrought test1 -r -d --verbose test2",
        ];

        for valid_line in valid_lines {
            clap_setup()
                .try_get_matches_from(valid_line.split(' '))
                .unwrap_or_else(|e| panic!("Error: {e} from command line: {}", &valid_line));
        }
    }

    #[test]
    fn invalid_command_lines_not_ok() {
        let valid_lines = [
            "bitwrought",
            "bitwrought -r",
            "bitwrought test -z",
            "bitwrought test -rdvz",
            "bitwrought test -r -d --verboze",
            "bitwrought test --verboze",
        ];

        for valid_line in valid_lines {
            clap_setup()
                .try_get_matches_from(valid_line.split(' '))
                .unwrap_err();
        }
    }

    #[test]
    fn valid_command_lines_parse() {
        fn s(string: &str) -> PathBuf {
            PathBuf::from(string)
        }
        let valid_lines = [
            "bitwrought test1 test2",
            "bitwrought a/b/c",
            "bitwrought test -rdv",
            "bitwrought test1 -r --verbose test2",
        ];

        let expected_values = [
            (vec![s("test1"), s("test2")], false, false, false),
            (vec![s("a/b/c")], false, false, false),
            (vec![s("test")], true, true, true),
            (vec![s("test1"), s("test2")], true, false, true),
        ];

        for i in 0..valid_lines.len() {
            let matches = parse_args(clap_setup(), valid_lines[i].split(' '));
            assert_eq!(matches, expected_values[i]);
        }
    }

    //2. test that different methods of calculating the hash all agree on a test file
    #[test]
    fn test_buffered_file_read_hash() {
        let mut file = tempfile().expect("cannot create tempfile in test");
        write_random_file(256, &mut file).expect("cant write to file in test");

        let buffered = calculate_file_digest_buffered(&mut file).expect("cant hash file");
        let non_buffered = calculate_file_digest(&mut file).expect("cant hash file");
        let buf_reader = calculate_file_digest_buf_reader(&mut file).expect("cant hash file");

        assert_eq!(buffered, non_buffered);
        assert_eq!(non_buffered, buf_reader);
    }

    //3. test that two different files have different hashes
    #[test]
    fn test_different_files_hash() {
        let mut f1 = tempfile().expect("cannot create tempfile in test");
        write_random_file(256, &mut f1).expect("cant write to file in test");

        let mut f2 = tempfile().expect("cannot create tempfile in test");
        write_random_file(256, &mut f2).expect("cant write to file in test");

        let f1_hash = calculate_file_digest_buffered(&mut f1).expect("cant hash file");
        let f2_hash = calculate_file_digest_buffered(&mut f2).expect("cant hash file");

        assert_ne!(f1_hash, f2_hash);
    }
    //4. test that a slightly changed file has a different hash
    #[test]
    fn test_rotted_file_hash() {
        let mut tf = tempfile::NamedTempFile::new().unwrap();

        write_random_file(256, &mut tf).unwrap();

        let tf_path = tf.path().to_str().unwrap();
        let mut tf_r = fs::File::open(tf_path).unwrap();
        let digest1 = calculate_file_digest_buffered(&mut tf_r).unwrap();

        rot_file(tf_path).unwrap();

        let mut tf_r = fs::File::open(tf_path).unwrap();
        // // file_r.seek(SeekFrom::Start(0)).unwrap();
        let digest2 = calculate_file_digest_buffered(&mut tf_r).unwrap();

        println!("a: {}", digest1);
        println!("b: {}", digest2);

        assert_ne!(digest1, digest2);
    }
    //5. test that we can detect a file without the custom xattr
    #[test]
    fn test_file_without_xattr() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let xattr_value = xattr::get(file.path(), HASH_XATTR).unwrap();
        assert!(xattr_value.is_none());
    }
    //6. test that we can detect a file with the custom xattr
    #[test]
    fn test_file_with_xattr() {
        let file = tempfile::NamedTempFile::new().unwrap();
        xattr::set(file.path(), HASH_XATTR, b"test").unwrap();
        let xattr_value = xattr::get(file.path(), HASH_XATTR).unwrap();
        assert!(xattr_value.is_some());
    }

    //7. test that it can differentiate rotten vs. written files
    #[test]
    fn detects_modified_files() {}
    //8. test that it can traverse directories shallowly
    #[test]
    fn traverses_dirs_shallow() {}
    //9. test that it can traverse directories recursively
    #[test]
    fn traverses_dirs_recursive() {}

    fn calculate_file_digest<T: Read + Seek>(file: &mut T) -> Result<String, Box<dyn Error>> {
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let hash = Sha256::digest(bytes);
        Ok(format!("{:x}", hash))
    }

    fn calculate_file_digest_buf_reader<T: Read + Seek>(
        file: &mut T,
    ) -> Result<String, Box<dyn Error>> {
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut hasher = Sha256::new();
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);

        let mut bytes_read = 1;
        while bytes_read > 0 {
            let buffer = reader.fill_buf().unwrap();
            hasher.update(buffer);
            bytes_read = buffer.len();
            reader.consume(bytes_read);
        }

        let digest = hasher.finalize();
        Ok(format!("{:x}", digest))
    }

    fn write_random_file<T: Write>(num_bytes: usize, file: &mut T) -> Result<(), Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..num_bytes).map(|_| rng.gen_range(32..126)).collect();
        file.write_all(&bytes)?;

        Ok(())
    }

    fn rot_file(path: &str) -> Result<(), Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let mut file = std::fs::File::open(path)?;
        let file_middle_byte = fs::metadata(path).unwrap().len() / 2;
        let tf = NamedTempFile::new()?;
        let tf_path = tf.path();

        let mut buffer = [0u8; BUFFER_SIZE];
        let mut writer = BufWriter::new(&tf);

        let mut rotten = false;
        let mut bytes_read = 1;
        let mut total_bytes_read: u64 = 0;

        while bytes_read > 0 {
            bytes_read = file.read(&mut buffer)?;
            total_bytes_read += u64::try_from(bytes_read).unwrap();

            if file_middle_byte < total_bytes_read && !rotten {
                rotten = true;
                let rand_buffer: Vec<u8> =
                    (0..BUFFER_SIZE).map(|_| rng.gen_range(32..126)).collect();
                writer.write_all(&rand_buffer)?;
            } else {
                writer.write_all(&buffer[..bytes_read])?;
            }
        }
        fs::rename(tf_path, path)?;
        Ok(())
    }
}
