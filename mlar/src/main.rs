use clap::{App, Arg, ArgMatches, SubCommand};
use ed25519_parser::{
    generate_keypair, parse_openssl_ed25519_privkey, parse_openssl_ed25519_pubkey,
};
use glob::Pattern;
use hex;
use humansize::{file_size_opts, FileSize};
use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::errors::{Error, FailSafeReadError};
use mla::helpers::linear_extract;
use mla::{ArchiveFailSafeReader, ArchiveFile, ArchiveReader, ArchiveWriter, Layers};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use tar::{Builder, Header};
use x25519_dalek;

// ----- Utils ------

/// Allow for different kind of output. As ArchiveWriter is parametrized over
/// a Writable type, ArchiveWriter<File> and ArchiveWriter<io::stdout>
/// can't coexist in the same code path.
enum OutputTypes {
    Stdout,
    File { file: File },
}

impl Write for OutputTypes {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            OutputTypes::Stdout => io::stdout().write(buf),
            OutputTypes::File { file } => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            OutputTypes::Stdout => io::stdout().flush(),
            OutputTypes::File { file } => file.flush(),
        }
    }
}

fn open_ecc_private_keys(matches: &ArgMatches) -> Result<Vec<x25519_dalek::StaticSecret>, Error> {
    let mut private_keys = Vec::new();
    if let Some(private_key_args) = matches.values_of_os("private_keys") {
        for private_key_arg in private_key_args {
            let mut file = File::open(private_key_arg)?;
            // Load the the ECC key in-memory and parse it
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            match parse_openssl_ed25519_privkey(&buf) {
                Err(_) => return Err(Error::InvalidECCKeyFormat),
                Ok(private_key) => private_keys.push(private_key),
            };
        }
    };
    Ok(private_keys)
}

fn open_ecc_public_keys(matches: &ArgMatches) -> Result<Vec<x25519_dalek::PublicKey>, Error> {
    let mut public_keys = Vec::new();
    if let Some(public_key_args) = matches.values_of_os("public_keys") {
        for public_key_arg in public_key_args {
            let mut file = File::open(public_key_arg)?;
            // Load the the ECC key in-memory and parse it
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            match parse_openssl_ed25519_pubkey(&buf) {
                Err(_) => return Err(Error::InvalidECCKeyFormat),
                Ok(public_key) => public_keys.push(public_key),
            };
        }
    }
    Ok(public_keys)
}

/// Return the ArchiveWriterConfig corresponding to provided arguments
fn config_from_matches(matches: &ArgMatches) -> ArchiveWriterConfig {
    let mut config = ArchiveWriterConfig::new();

    // Get layers
    let mut layers = Vec::new();
    if matches.is_present("layers") {
        // Safe to use unwrap() because of the is_present() test
        for layer in matches.values_of("layers").unwrap() {
            layers.push(layer);
        }
    } else {
        // Default
        layers.push("compress");
        layers.push("encrypt");
    };

    for layer in layers {
        if layer == "compress" {
            config.enable_layer(Layers::COMPRESS);
        } else if layer == "encrypt" {
            config.enable_layer(Layers::ENCRYPT);
        } else {
            panic!("[ERROR] Unknown layer {}", layer);
        }
    }

    // Encryption specifics
    if matches.is_present("public_keys") {
        if !config.is_layers_enabled(Layers::ENCRYPT) {
            eprintln!(
                "[WARNING] 'public_keys' argument ignored, because 'encrypt' layer is not enabled"
            );
        } else {
            let public_keys = match open_ecc_public_keys(matches) {
                Ok(public_keys) => public_keys,
                Err(error) => {
                    panic!("[ERROR] Unable to open public keys: {}", error);
                }
            };
            config.add_public_keys(&public_keys);
        }
    }

    // Compression specifics
    if matches.is_present("compression_level") {
        if !config.is_layers_enabled(Layers::COMPRESS) {
            eprintln!("[WARNING] 'compression_level' argument ignored, because 'compress' layer is not enabled");
        } else {
            let comp_level: u32 = matches
                .value_of("compression_level")
                .unwrap()
                .parse()
                .expect("compression_level must be an int");
            if comp_level > 11 {
                panic!("compression_level must be in [0 .. 11]");
            }
            config.with_compression_level(comp_level).unwrap();
        }
    }

    config
}

fn destination_from_output_argument(output_argument: &str) -> Result<OutputTypes, Error> {
    let destination = if output_argument != "-" {
        let path = Path::new(&output_argument);
        OutputTypes::File {
            file: File::create(&path)?,
        }
    } else {
        OutputTypes::Stdout
    };
    Ok(destination)
}

/// Return an ArchiveWriter corresponding to provided arguments
fn writer_from_matches<'a>(matches: &ArgMatches) -> Result<ArchiveWriter<'a, OutputTypes>, Error> {
    let config = config_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let output = matches.value_of("output").unwrap();

    let destination = destination_from_output_argument(output)?;

    // Instantiate output writer
    ArchiveWriter::from_config(destination, config)
}

/// Return the ArchiveReaderConfig corresponding to provided arguments
fn readerconfig_from_matches(matches: &ArgMatches) -> ArchiveReaderConfig {
    let mut config = ArchiveReaderConfig::new();

    if matches.is_present("private_keys") {
        let private_keys = match open_ecc_private_keys(matches) {
            Ok(private_keys) => private_keys,
            Err(error) => {
                panic!("[ERROR] Unable to open private keys: {}", error);
            }
        };
        config.add_private_keys(&private_keys);
    }

    config
}

fn open_mla_file<'a>(matches: &ArgMatches) -> Result<ArchiveReader<'a, File>, Error> {
    let config = readerconfig_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let mla_file = matches.value_of("input").unwrap();
    let path = Path::new(&mla_file);
    let file = File::open(&path)?;

    // Instantiate reader
    ArchiveReader::from_config(file, config)
}

// Utils: common code to load a mla_file from arguments, fail-safe mode
fn open_failsafe_mla_file<'a>(
    matches: &ArgMatches,
) -> Result<ArchiveFailSafeReader<'a, File>, Error> {
    let config = readerconfig_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let mla_file = matches.value_of("input").unwrap();
    let path = Path::new(&mla_file);
    let file = File::open(&path)?;

    // Instantiate reader
    ArchiveFailSafeReader::from_config(file, config)
}

fn add_file_to_tar<R: Read, W: Write>(
    tar_file: &mut Builder<W>,
    sub_file: ArchiveFile<R>,
) -> Result<(), Error> {
    // Use indexes to avoid in-memory copy
    let mut header = Header::new_gnu();
    header.set_size(sub_file.size);
    header.set_mode(0o444); // Create files as read-only
    header.set_cksum();

    // Force relative path, the trivial way (does not support Windows paths)
    let filename = {
        if Path::new(&sub_file.filename).is_absolute() {
            format!("./{}", sub_file.filename)
        } else {
            sub_file.filename
        }
    };

    if let Err(why) = tar_file.append_data(&mut header, &filename, sub_file.data) {
        panic!(
            "Error while adding file \"{}\" to tarball: {}",
            filename, why
        );
    }
    Ok(())
}

/// Arguments for action 'extract' to match file names in the archive
enum ExtractFileNameMatcher {
    /// Match a list of files, where the order does not matter
    Files(HashSet<String>),
    /// Match a list of glob patterns
    GlobPatterns(Vec<Pattern>),
    /// No matching argument has been provided, so match all files
    Anything,
}
impl ExtractFileNameMatcher {
    fn from_matches(matches: &ArgMatches) -> Self {
        let files = match matches.values_of("files") {
            Some(values) => values,
            None => return ExtractFileNameMatcher::Anything,
        };
        if matches.is_present("glob") {
            // Use glob patterns
            ExtractFileNameMatcher::GlobPatterns(
                files
                    .map(|pat| {
                        Pattern::new(pat)
                            .map_err(|err| {
                                eprintln!("[!] Invalid glob pattern {:?} ({:?})", pat, err);
                            })
                            .expect("Invalid glob pattern")
                    })
                    .collect(),
            )
        } else {
            // Use file names
            ExtractFileNameMatcher::Files(files.map(|s| s.to_string()).collect())
        }
    }
    fn match_file_name(&self, file_name: &str) -> bool {
        match self {
            ExtractFileNameMatcher::Files(ref files) => {
                files.is_empty() || files.contains(file_name)
            }
            ExtractFileNameMatcher::GlobPatterns(ref patterns) => {
                patterns.is_empty() || patterns.iter().any(|pat| pat.matches(&file_name))
            }
            ExtractFileNameMatcher::Anything => true,
        }
    }
}

/// Compute the full path of the final file, using defensive measures
/// similar as what tar-rs does for `Entry::unpack_in`:
/// https://github.com/alexcrichton/tar-rs/blob/0.4.26/src/entry.rs#L344
fn get_extracted_path(output_dir: &Path, file_name: &str) -> Option<PathBuf> {
    let mut file_dst = output_dir.to_path_buf();
    for part in Path::new(&file_name).components() {
        match part {
            // Leading '/' characters, root paths, and '.'
            // components are just ignored and treated as "empty
            // components"
            Component::Prefix(..) | Component::RootDir | Component::CurDir => continue,

            // If any part of the filename is '..', then skip over
            // unpacking the file to prevent directory traversal
            // security issues.  See, e.g.: CVE-2001-1267,
            // CVE-2002-0399, CVE-2005-1918, CVE-2007-4131
            Component::ParentDir => {
                eprintln!(
                    "[!] Skipping file \"{}\" because it contains \"..\"",
                    file_name
                );
                return None;
            }

            Component::Normal(part) => file_dst.push(part),
        }
    }
    Some(file_dst)
}

/// Create a file and associate parent directories in a given output directory
fn create_file<P1: AsRef<Path>>(
    output_dir: P1,
    fname: &str,
) -> Result<Option<(File, PathBuf)>, Error> {
    let extracted_path = match get_extracted_path(output_dir.as_ref(), &fname) {
        Some(p) => p,
        None => return Ok(None),
    };
    // Create all directories leading to the file
    let containing_directory = match extracted_path.parent() {
        Some(p) => p,
        None => {
            eprintln!(
                "[!] Skipping file \"{}\" because it does not have a parent (from {})",
                &fname,
                extracted_path.display()
            );
            return Ok(None);
        }
    };
    if !containing_directory.exists() {
        fs::create_dir_all(&containing_directory).map_err(|err| {
            eprintln!(
                " [!] Error while creating output directory path for \"{}\" ({:?})",
                output_dir.as_ref().display(),
                err
            );
            err
        })?;
    }

    // Ensure that the containing directory is in the output dir
    let containing_directory = fs::canonicalize(&containing_directory).map_err(|err| {
        eprintln!(
            " [!] Error while canonicalizing extracted file output directory path \"{}\" ({:?})",
            containing_directory.display(),
            err
        );
        err
    })?;
    if !containing_directory.starts_with(output_dir) {
        eprintln!(
            " [!] Skipping file \"{}\" because it would be extracted outside of the output directory, in {}",
            fname, containing_directory.display()
        );
        return Ok(None);
    }
    Ok(Some((
        File::create(&extracted_path).map_err(|err| {
            eprintln!(" [!] Unable to create \"{}\" ({:?})", fname, err);
            err
        })?,
        extracted_path,
    )))
}

/// Wrapper with Write, to append data to a file
///
/// This wrapper is used to avoid opening all files simultaneously, potentially
/// reaching the filesystem limit, but rather appending to file on-demand
/// This could be enhanced with a limited pool of active file, but this
/// optimisation doesn't seems necessary for now
struct FileWriter {
    /// Target file for data appending
    path: PathBuf,
}

impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        fs::OpenOptions::new()
            .append(true)
            .open(&self.path)?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ----- Commands ------

fn create(matches: &ArgMatches) -> Result<(), Error> {
    let mut mla = writer_from_matches(matches)?;

    if let Some(files) = matches.values_of("files") {
        for filename in files {
            eprintln!("{}", filename);
            let file = File::open(&Path::new(&filename))?;
            let length = file.metadata()?.len();
            mla.add_file(filename, length, file)?;
        }
    };

    mla.finalize()?;
    Ok(())
}

fn list(matches: &ArgMatches) -> Result<(), Error> {
    let mut mla = open_mla_file(matches)?;

    let mut iter: Vec<String> = mla.list_files()?.cloned().collect();
    iter.sort();
    for fname in iter {
        if matches.is_present("verbose") {
            let mla_file = mla.get_file(fname)?.expect("Unable to get the file");
            let filename = mla_file.filename;
            let size = mla_file
                .size
                .file_size(file_size_opts::CONVENTIONAL)
                .unwrap();
            if matches.occurrences_of("verbose") == 1 {
                println!("{} - {}", filename, size);
            } else if matches.occurrences_of("verbose") >= 2 {
                let hash = mla.get_hash(&filename)?.expect("Unable to get the hash");
                println!("{} - {} ({})", filename, size, hex::encode(hash),);
            }
        } else {
            println!("{}", fname);
        }
    }
    Ok(())
}

fn extract(matches: &ArgMatches) -> Result<(), Error> {
    let file_name_matcher = ExtractFileNameMatcher::from_matches(&matches);
    let output_dir = Path::new(matches.value_of_os("outputdir").unwrap());
    let verbose = matches.is_present("verbose");

    let mut mla = open_mla_file(matches)?;

    // Create the output directory, if it does not exist
    if !output_dir.exists() {
        fs::create_dir(&output_dir).map_err(|err| {
            eprintln!(
                " [!] Error while creating output directory \"{}\" ({:?})",
                output_dir.display(),
                err
            );
            err
        })?;
    }
    let output_dir = fs::canonicalize(&output_dir).map_err(|err| {
        eprintln!(
            " [!] Error while canonicalizing output directory path \"{}\" ({:?})",
            output_dir.display(),
            err
        );
        err
    })?;

    let mut iter: Vec<String> = mla.list_files()?.cloned().collect();
    iter.sort();

    if let ExtractFileNameMatcher::Anything = file_name_matcher {
        // Optimisation: use linear extraction
        if verbose {
            println!("Extracting the whole archive using a linear extraction");
        }
        let mut export: HashMap<&String, FileWriter> = HashMap::new();
        for fname in &iter {
            match create_file(&output_dir, fname)? {
                Some((_file, path)) => {
                    export.insert(fname, FileWriter { path });
                }
                None => continue,
            }
        }
        return linear_extract(&mut mla, &mut export);
    }

    for fname in iter {
        // Filter files according to glob patterns or files given as parameters
        if !file_name_matcher.match_file_name(&fname) {
            continue;
        }

        // Look for the file in the archive
        let mut sub_file = match mla.get_file(fname.clone()) {
            Err(err) => {
                eprintln!(
                    " [!] Error while looking up subfile \"{}\" ({:?})",
                    fname, err
                );
                continue;
            }
            Ok(None) => {
                eprintln!(
                    " [!] Subfile \"{}\" indexed in metadata could not be found",
                    fname
                );
                continue;
            }
            Ok(Some(subfile)) => subfile,
        };
        let (mut extracted_file, _path) = match create_file(&output_dir, &fname)? {
            Some(file) => file,
            None => continue,
        };

        if verbose {
            println!("{}", fname);
        }
        io::copy(&mut sub_file.data, &mut extracted_file).map_err(|err| {
            eprintln!(" [!] Unable to extract \"{}\" ({:?})", fname, err);
            err
        })?;
    }
    Ok(())
}

fn cat(matches: &ArgMatches) -> Result<(), Error> {
    let files_values = matches.values_of("files").unwrap();
    let output = matches.value_of("output").unwrap();
    let mut destination = destination_from_output_argument(output)?;

    let mut mla = open_mla_file(matches)?;
    if matches.is_present("glob") {
        // For each glob patterns, enumerate matching files and display them
        let mut archive_files: Vec<String> = mla.list_files()?.cloned().collect();
        archive_files.sort();
        for arg_pattern in files_values {
            let pat = match Pattern::new(arg_pattern) {
                Ok(pat) => pat,
                Err(err) => {
                    eprintln!(" [!] Invalid glob pattern {:?} ({:?})", arg_pattern, err);
                    continue;
                }
            };
            for fname in archive_files.iter() {
                if !pat.matches(fname) {
                    continue;
                }
                match mla.get_file(fname.to_string()) {
                    Err(err) => {
                        eprintln!(" [!] Error while looking up file \"{}\" ({:?})", fname, err);
                        continue;
                    }
                    Ok(None) => {
                        eprintln!(
                            " [!] Subfile \"{}\" indexed in metadata could not be found",
                            fname
                        );
                        continue;
                    }
                    Ok(Some(mut subfile)) => {
                        io::copy(&mut subfile.data, &mut destination).map_err(|err| {
                            eprintln!(" [!] Unable to extract \"{}\" ({:?})", fname, err);
                            err
                        })?;
                    }
                }
            }
        }
    } else {
        // Retrieve all the files that are specified
        for fname in files_values {
            match mla.get_file(fname.to_string()) {
                Err(err) => {
                    eprintln!(" [!] Error while looking up file \"{}\" ({:?})", fname, err);
                    continue;
                }
                Ok(None) => {
                    eprintln!(" [!] File not found: \"{}\"", fname);
                    continue;
                }
                Ok(Some(mut subfile)) => {
                    io::copy(&mut subfile.data, &mut destination).map_err(|err| {
                        eprintln!(" [!] Unable to extract \"{}\" ({:?})", fname, err);
                        err
                    })?;
                }
            }
        }
    }
    Ok(())
}

fn to_tar(matches: &ArgMatches) -> Result<(), Error> {
    let mut mla = open_mla_file(matches)?;

    // Safe to use unwrap() because the option is required()
    let output = matches.value_of("output").unwrap();
    let path = Path::new(&output);
    let mut tar_file = Builder::new(File::create(&path)?);

    let iter = mla.list_files()?;
    let fnames: Vec<String> = iter.cloned().collect();
    for fname in fnames {
        let sub_file = match mla.get_file(fname.clone()) {
            Err(err) => {
                eprintln!(
                    " [!] Error while looking up subfile \"{}\" ({:?})",
                    fname, err
                );
                continue;
            }
            Ok(None) => {
                eprintln!(
                    " [!] Subfile \"{}\" indexed in metadata could not be found",
                    fname
                );
                continue;
            }
            Ok(Some(subfile)) => subfile,
        };
        if let Err(err) = add_file_to_tar(&mut tar_file, sub_file) {
            eprintln!(" [!] Unable to add subfile \"{}\" ({:?})", fname, err);
        }
    }
    Ok(())
}

fn repair(matches: &ArgMatches) -> Result<(), Error> {
    let mut mla = open_failsafe_mla_file(matches)?;
    let mut mla_out = writer_from_matches(matches)?;

    // Convert
    let status = mla.convert_to_archive(&mut mla_out)?;
    match status {
        FailSafeReadError::NoError => {}
        FailSafeReadError::EndOfOriginalArchiveData => {
            eprintln!("[WARNING] The whole archive has been recovered");
        }
        _ => {
            eprintln!("[WARNING] Conversion ends with {}", status);
        }
    };
    Ok(())
}

fn convert(matches: &ArgMatches) -> Result<(), Error> {
    let mut mla = open_mla_file(matches)?;
    let mut fnames: Vec<String> = if let Ok(iter) = mla.list_files() {
        // Read the file list using metadata
        iter.cloned().collect()
    } else {
        panic!("Files is malformed. Please consider repairing the file");
    };
    fnames.sort();

    let mut mla_out = writer_from_matches(matches)?;

    // Convert
    for fname in fnames {
        eprintln!("{}", fname);
        let sub_file = match mla.get_file(fname.clone()) {
            Err(err) => {
                eprintln!("Error while adding {} ({:?})", fname, err);
                continue;
            }
            Ok(None) => {
                eprintln!("Unable to found {}", fname);
                continue;
            }
            Ok(Some(mla)) => mla,
        };
        mla_out.add_file(&sub_file.filename, sub_file.size, sub_file.data)?;
    }
    mla_out.finalize().expect("Finalization error");

    Ok(())
}

fn keygen(matches: &ArgMatches) -> Result<(), Error> {
    // Safe to use unwrap() because of the requirement
    let output_base = matches.value_of_os("output").unwrap();

    let mut output_pub = File::create(Path::new(output_base).with_extension("pub"))
        .expect("Unable to create the public file");
    let mut output_priv = File::create(output_base).expect("Unable to create the private file");

    let mut csprng = ChaChaRng::from_entropy();
    let key_pair = generate_keypair(&mut csprng).expect("Error while generating the key-pair");

    // Output the public key in PEM format, to ease integration in text based
    // configs
    output_pub
        .write_all(&key_pair.public_as_pem().as_bytes())
        .expect("Error writing the public key");

    // Output the private key in DER format, to avoid common mistakes
    output_priv
        .write_all(&key_pair.private_der)
        .expect("Error writing the private key");
    Ok(())
}

fn main() {
    // Common arguments list, for homogeneity
    let input_args = vec![
        Arg::with_name("input")
            .help("Archive path")
            .long("input")
            .short("i")
            .number_of_values(1)
            .required(true),
        Arg::with_name("private_keys")
            .long("private_keys")
            .short("k")
            .help("Candidates ED25519 private key paths (DER or PEM format)")
            .number_of_values(1)
            .multiple(true)
            .takes_value(true),
    ];
    let layers = ["compress", "encrypt"];
    let output_args = vec![
        Arg::with_name("output")
            .help("Output file path. Use - for stdout")
            .long("output")
            .short("o")
            .takes_value(true)
            .required(true),
        Arg::with_name("public_keys")
            .help("ED25519 Public key paths (DER or PEM format)")
            .long("pubkey")
            .short("p")
            .number_of_values(1)
            .multiple(true),
        Arg::with_name("layers")
            .long("layers")
            .short("l")
            .help("Layers to use. Default is 'compress,encrypt'")
            .possible_values(&layers)
            .number_of_values(1)
            .multiple(true)
            .min_values(0),
        Arg::with_name("compression_level")
            .group("Compression layer")
            .short("-q")
            .long("compression_level")
            .help("Compression level (0-11); ; bigger values cause denser, but slower compression")
            .takes_value(true),
    ];

    // Main parsing
    let mut app = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            SubCommand::with_name("create")
                .about("Create a new MLA Archive")
                .args(&output_args)
                .arg(Arg::with_name("files").help("Files to add").multiple(true)),
        )
        .subcommand(
            SubCommand::with_name("list")
                .about("List files inside a MLA Archive")
                .args(&input_args)
                .arg(
                    Arg::with_name("verbose")
                        .short("-v")
                        .multiple(true)
                        .takes_value(false)
                        .help("Verbose listing, with additional information"),
                ),
        )
        .subcommand(
            SubCommand::with_name("extract")
                .about("Extract files from a MLA Archive")
                .args(&input_args)
                .arg(
                    Arg::with_name("outputdir")
                        .help("Output directory where files are extracted")
                        .long("output")
                        .short("o")
                        .number_of_values(1)
                        .default_value("."),
                )
                .arg(
                    Arg::with_name("glob")
                        .long("glob")
                        .short("-g")
                        .takes_value(false)
                        .help("Treat specified files as glob patterns"),
                )
                .arg(Arg::with_name("files").help("List of extracted files (all if none given)"))
                .arg(
                    Arg::with_name("verbose")
                        .long("verbose")
                        .short("-v")
                        .takes_value(false)
                        .help("List files as they are extracted"),
                ),
        )
        .subcommand(
            SubCommand::with_name("cat")
                .about("Display files from a MLA Archive, like 'cat'")
                .args(&input_args)
                .arg(
                    Arg::with_name("output")
                        .help("Output file where files are displayed")
                        .long("output")
                        .short("o")
                        .number_of_values(1)
                        .default_value("-"),
                )
                .arg(
                    Arg::with_name("glob")
                        .long("glob")
                        .short("-g")
                        .takes_value(false)
                        .help("Treat given files as glob patterns"),
                )
                .arg(
                    Arg::with_name("files")
                        .required(true)
                        .help("List of displayed files"),
                ),
        )
        .subcommand(
            SubCommand::with_name("to-tar")
                .about("Convert a MLA Archive to a TAR Archive")
                .args(&input_args)
                .arg(
                    Arg::with_name("output")
                        .help("Tar Archive path")
                        .long("output")
                        .short("o")
                        .number_of_values(1)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("repair")
                .about("Try to repair a MLA Archive into a fresh MLA Archive")
                .args(&input_args)
                .args(&output_args),
        )
        .subcommand(
            SubCommand::with_name("convert")
                .about(
                    "Convert a MLA Archive to a fresh new one, with potentially different options",
                )
                .args(&input_args)
                .args(&output_args),
        )
        .subcommand(
            SubCommand::with_name("keygen")
                .about(
                    "Generate a public/private keypair, in OpenSSL Ed25519 format, to be used by mlar",
                )
                .arg(
                    Arg::with_name("output")
                        .help("Output file for the private key. The public key is in {output}.pub")
                        .number_of_values(1)
                        .required(true)
                )
        );

    // Launch sub-command
    let mut help = Vec::new();
    app.write_long_help(&mut help).unwrap();
    let matches = app.get_matches();
    let res = if let Some(matches) = matches.subcommand_matches("create") {
        create(matches)
    } else if let Some(matches) = matches.subcommand_matches("list") {
        list(matches)
    } else if let Some(matches) = matches.subcommand_matches("extract") {
        extract(matches)
    } else if let Some(matches) = matches.subcommand_matches("cat") {
        cat(matches)
    } else if let Some(matches) = matches.subcommand_matches("to-tar") {
        to_tar(matches)
    } else if let Some(matches) = matches.subcommand_matches("repair") {
        repair(matches)
    } else if let Some(matches) = matches.subcommand_matches("convert") {
        convert(matches)
    } else if let Some(matches) = matches.subcommand_matches("keygen") {
        keygen(matches)
    } else {
        eprintln!("Error: at least one command required.");
        eprintln!("{}", std::str::from_utf8(&help).unwrap());
        std::process::exit(1);
    };

    if let Err(err) = res {
        eprintln!("[!] Command ended with error: {:?}", err);
        std::process::exit(1);
    }
}
