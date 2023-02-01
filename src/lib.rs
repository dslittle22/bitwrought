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

    let mut all_filepaths: Vec<PathBuf> = Vec::new();

    for path in paths {
        let path_metadata = fs::metadata(&path);
        if path_metadata.is_err() {
            all_filepaths.push(path);
            continue;
        }
        if path_metadata.unwrap().is_dir() {
            match traverse_dir(&path, recursive) {
                Ok(mut filepaths) => all_filepaths.append(&mut filepaths),
                Err(e) => {
                    println!(
                        "Error when traversing directory \"{}\". Error: {e}",
                        path.to_str().unwrap_or_default()
                    )
                }
            }
        } else {
            all_filepaths.push(path);
        }
    }

    if verbose {
        let all_filepaths_str = all_filepaths
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
            "All file paths collected: {all_filepaths_str}.\nAttempting to {action} all files."
        );
    }

    if all_filepaths.len() > 10 {
        many_files_warning(all_filepaths.len());
    }

    let mut result_strings: Vec<String> = Vec::new();

    for filepath in all_filepaths {
        let status = if delete {
            Ok(delete_xattrs(&filepath))
        } else {
            check(&filepath, verbose)
        };

        let filepath_str = filepath.to_str().unwrap_or_default();
        match status {
            Ok(file_status) => {
                result_strings.push(format!("File \"{filepath_str}\": {file_status}"));
            }
            Err(err) => {
                println!("Operating on file \"{filepath_str}\" caused an error: {err}");
            }
        }
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
        std::io::stdin()
            .read_line(&mut line)
            .expect("Sorry, error parsing your response!");

        if !&line.eq("Yes\n") {
            exit(0);
        }
    }
    Ok(())
}

#[derive(PartialEq, Debug)]
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

fn check(path: &Path, verbose: bool) -> Result<FileStatus, Box<dyn Error>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(FileStatus::DoesNotExist),
    };

    if metadata.permissions().readonly() {
        return Ok(FileStatus::BadPermissions);
    }

    let saved_hash = get_xattr(path, HASH_XATTR);

    if saved_hash.is_empty() {
        save_file_hash(path)?;
        Ok(FileStatus::Ok(String::from(
            "File has no hash saved. Calculating and storing now.",
        )))
    } else {
        let hash = calculate_file_digest_buffered(path)?;
        if verbose {
            let path_str = path.display();
            println!("File \"{path_str}\" hash previously saved: {saved_hash}");
            println!("File \"{path_str}\" newly calculated hash: {hash}");
        }

        if saved_hash == hash {
            Ok(FileStatus::Ok(String::from(
                "File hash matches previously saved result.",
            )))
        } else {
            let saved_timestamp = get_xattr(path, MODIFIED_XATTR);
            let last_modified = get_last_modified(path)?;

            if verbose {
                let path_str = path.display();
                println!("Modified timestamp for file \"{path_str}\" previously saved in bitwrought: {saved_timestamp}");
                println!("Modified timestamp from file \"{path_str}\" metadata: {last_modified}");
            }

            if last_modified > saved_timestamp {
                save_file_hash(path)?;
                Ok(FileStatus::Modified)
            } else {
                Ok(FileStatus::Rotten)
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

fn clap_setup() -> Command {
    Command::new("bitwrought")
        .version("0.1")
        .author("Danny Little")
        .about("Detects changes in files and notifies of these changes when run.")
        .after_help(
            "Bitwrought will look at each file passed to it, and checks if it has a hash saved.
If it does, it recalculates the file's hash and compares it to the saved one.
If not, it calculates a new one and saves it to the file in a custom xattr.
If passed a directory, bitwrought will check each file with a shallow traversal.
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

fn calculate_file_digest_buffered(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(0))?;
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
    let hash = calculate_file_digest_buffered(path)?;
    xattr::set(path, HASH_XATTR, hash.as_bytes())?;
    let time = get_xattr(path, MODIFIED_XATTR);
    if time.is_empty() {
        let last_modified = get_last_modified(path)?;
        xattr::set(path, MODIFIED_XATTR, last_modified.as_bytes())?;
    }
    Ok(())
}

fn traverse_dir(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut all_files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() && recursive {
            let mut dir_files = traverse_dir(&path, true)?;
            all_files.append(&mut dir_files);
        } else if !path.is_dir() && !should_ignore(&path) {
            all_files.push(entry.path());
        }
    }
    Ok(all_files)
}

fn get_xattr(path: &Path, key: &str) -> String {
    let xattr_bytes = xattr::get(path, key).unwrap_or(Some(Vec::new()));
    let xattr_bytes = xattr_bytes.unwrap_or_default();
    String::from_utf8(xattr_bytes).unwrap_or_default()
}

fn get_last_modified(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(fs::metadata(path)?
        .modified()?
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_string())
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
    use tempfile::{tempdir, NamedTempFile};

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

    //test that different methods of calculating the hash all agree on a test file
    #[test]
    fn test_buffered_file_read_hash() {
        let mut file = NamedTempFile::new().unwrap();
        write_random_file(256, &mut file).unwrap();

        let buffered = calculate_file_digest_buffered(file.path()).unwrap();
        let non_buffered = calculate_file_digest(&mut file).unwrap();
        let buf_reader = calculate_file_digest_buf_reader(&mut file).unwrap();

        assert_eq!(buffered, non_buffered);
        assert_eq!(non_buffered, buf_reader);
    }

    //test that two different files have different hashes
    #[test]
    fn test_different_files_hash() {
        let mut f1 = NamedTempFile::new().unwrap();
        write_random_file(256, &mut f1).unwrap();

        let mut f2 = NamedTempFile::new().unwrap();
        write_random_file(256, &mut f2).unwrap();

        let f1_hash = calculate_file_digest_buffered(f1.path()).unwrap();
        let f2_hash = calculate_file_digest_buffered(f2.path()).unwrap();

        assert_ne!(f1_hash, f2_hash);
    }
    //test that a slightly changed file has a different hash
    #[test]
    fn test_rotted_file_hash() {
        let mut tf = NamedTempFile::new().unwrap();
        write_random_file(256, &mut tf).unwrap();
        let digest1 = calculate_file_digest_buffered(tf.path()).unwrap();

        rot_file(&PathBuf::from(tf.path())).unwrap();
        let digest2 = calculate_file_digest_buffered(tf.path()).unwrap();

        assert_ne!(digest1, digest2);
    }

    //test that we can detect a file without the custom xattr
    #[test]
    fn test_file_without_xattr() {
        let file = NamedTempFile::new().unwrap();
        let xattr_value = get_xattr(file.path(), HASH_XATTR);
        assert!(xattr_value.is_empty());
    }

    //test that we can detect a file with the custom xattr
    #[test]
    fn test_file_with_xattr() {
        let file = NamedTempFile::new().unwrap();
        xattr::set(file.path(), HASH_XATTR, b"test").unwrap();
        let xattr_value = get_xattr(file.path(), HASH_XATTR);
        assert!(!xattr_value.is_empty());
    }

    fn add_secs(timestamp: &str, secs: i64) -> String {
        use chrono::{DateTime, Local, NaiveDateTime, Utc};
        let mut timestamp = timestamp.parse::<i64>().unwrap_or_default();
        timestamp += secs;
        let dt = DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp_opt(timestamp, 0).unwrap(),
            Utc,
        );
        let dt: DateTime<Local> = DateTime::from(dt);
        format!("{}", dt.format("%Y%m%d%H%M"))
    }

    //test that check() detects written files
    #[test]
    fn detects_modified_files() {
        let mut file = NamedTempFile::new().unwrap();
        write_random_file(256, &mut file).unwrap();
        check(file.path(), false).unwrap();

        rot_file(file.path()).unwrap();

        let saved_timestamp = get_xattr(file.path(), MODIFIED_XATTR);
        let new_timestamp = add_secs(&saved_timestamp, 1_000_000);

        std::process::Command::new("touch")
            .arg("-t")
            .arg(&new_timestamp)
            .arg(file.path())
            .output()
            .unwrap();

        let status = check(file.path(), false).unwrap();
        assert_eq!(status, FileStatus::Modified);
    }

    // test that check() detects rotten files
    #[test]
    fn detects_rotten_files() {
        let mut file = NamedTempFile::new().unwrap();
        write_random_file(256, &mut file).unwrap();
        check(file.path(), false).unwrap();

        rot_file(file.path()).unwrap();

        let saved_timestamp = get_xattr(file.path(), MODIFIED_XATTR);
        let new_timestamp = add_secs(&saved_timestamp, -1_000_000);

        std::process::Command::new("touch")
            .arg("-t")
            .arg(&new_timestamp)
            .arg(file.path())
            .output()
            .unwrap();

        let status = check(file.path(), false).unwrap();
        assert_eq!(status, FileStatus::Rotten);
    }

    //test that it can traverse directories shallowly
    #[test]
    fn traverses_dirs_shallow() {
        let dir = tempdir().unwrap();
        fs::File::create(dir.path().join("a")).unwrap();
        fs::File::create(dir.path().join("b")).unwrap();
        fs::create_dir(dir.path().join("c")).unwrap();
        fs::File::create(dir.path().join("c").join("a")).unwrap();
        let mut files = traverse_dir(dir.path(), false).unwrap();
        let mut result = vec![dir.path().join("a"), dir.path().join("b")];
        files.sort();
        result.sort();
        assert_eq!(files, result);
    }
    // test that it can traverse directories recursively
    #[test]
    fn traverses_dirs_recursive() {
        let dir = tempdir().unwrap();
        fs::File::create(dir.path().join("a")).unwrap();
        fs::File::create(dir.path().join("b")).unwrap();
        fs::create_dir(dir.path().join("c")).unwrap();
        fs::File::create(dir.path().join("c").join("a")).unwrap();
        let mut files = traverse_dir(dir.path(), true).unwrap();
        let mut result = vec![
            dir.path().join("a"),
            dir.path().join("b"),
            dir.path().join("c").join("a"),
        ];
        files.sort();
        result.sort();
        assert_eq!(files, result)
    }

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

    fn rot_file(path: &Path) -> Result<(), Box<dyn Error>> {
        let saved_hash = get_xattr(path, HASH_XATTR);
        let saved_mod = get_xattr(path, MODIFIED_XATTR);

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
        xattr::set(path, HASH_XATTR, saved_hash.as_bytes())?;
        xattr::set(path, MODIFIED_XATTR, saved_mod.as_bytes())?;
        Ok(())
    }
}
