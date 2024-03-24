use clap::Parser;
use bcrypt::{DEFAULT_COST, hash};
use color_eyre::eyre;

#[derive(Parser)]
#[command(version)]
struct CliArg {
    /// Password to hash
    #[arg(short, long)]
    password: String,
}

fn main() -> Result<(), eyre::Error> {
    // Lets get pretty error reports
    color_eyre::install()?;

    // Pull in arg and get the password we want to hash
    let arg = CliArg::parse();

    // Hash password
    let hash_str = hash(arg.password, DEFAULT_COST)?;

    // Print password_hash to screen
    println!("Password hash: {}", hash_str);

    Ok(())
}
