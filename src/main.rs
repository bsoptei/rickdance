use aesstream::{AesReader, AesWriter};
use colored::*;
use crypto::aessafe::{AesSafe128Decryptor, AesSafe128Encryptor};

use std::{
    env,
    fs::File,
    io::{Read, Write},
};

type Res = Result<(), std::io::Error>;

fn main() {

    let args: Vec<String> = env::args().collect();
    let arg = |i: usize| args.get(i);

    let success = match (arg(1), arg(2), arg(3), arg(4)) {
        (Some(task), Some(input_path), Some(output_path), Some(user_key))
        if user_key.len() == 16 => {

            let key: &[u8] = user_key.as_bytes();

            println!(
                "{}",
                "Processing...".cyan()
            );

            match task.as_str() {
                "encrypt" => encrypt_file(input_path, output_path, key).is_ok(),
                "decrypt" => decrypt_file(input_path, output_path, key).is_ok(),
                _         => {
                    println!(
                        "{}",
                        "Unknown task.".bright_red()
                    );
                    false
                }
            }
        },
        _ => {
            println!(
                "{}",
                "Wrong arguments.".bright_red()
            );
            false
        }
    };

    if success {
        println!(
            "{}",
            format!(
                "Successfully finished {}ing.", // usually encrypting/decrypting xD
                arg(1).unwrap()
            ).green()
        );
    };

}

fn encrypt_file(input_file: &str, output_file: &str, user_key: &[u8]) -> Res {
    let mut file_to_read = File::open(input_file)?;
    let file_to_write = File::create(output_file)?;

    let encryptor = AesSafe128Encryptor::new(user_key);

    let mut contents = String::new();
    file_to_read .read_to_string(&mut contents)?;

    let mut writer = AesWriter::new(file_to_write, encryptor)?;
    writer.write_all(contents.as_bytes())?;

    Ok(())
}

fn decrypt_file(input_file: &str, output_file: &str, user_key: &[u8]) -> Res {
    let file_to_read = File::open(input_file)?;
    let mut file_to_write = File::create(output_file)?;

    let decryptor = AesSafe128Decryptor::new(user_key);

    let mut reader = AesReader::new(file_to_read, decryptor)?;
    let mut decrypted = String::new();
    reader.read_to_string(&mut decrypted)?;

    file_to_write.write_all(decrypted.as_bytes())?;

    Ok(())
}
