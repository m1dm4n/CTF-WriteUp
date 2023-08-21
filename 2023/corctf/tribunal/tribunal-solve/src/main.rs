extern crate solana_program;

use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_instruction, system_program,
    msg
};
use std::net::TcpStream;
use std::{error::Error, fs, io::prelude::*, io::BufReader, str::FromStr};

fn get_line<R: Read>(reader: &mut BufReader<R>) -> Result<String, Box<dyn Error>> {
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let ret = line
        .split(':')
        .nth(1)
        .ok_or("invalid input")?
        .trim()
        .to_string();

    Ok(ret)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:8080")?;
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let so_data = fs::read("../solve/target/deploy/solve.so")?;
    let solve_id = Pubkey::from_str("28prS7e14Fsm97GE5ws2YpjxseFNkiA33tB5D3hLZv3t").expect("solve public key error");
    {
        let mut intro = vec![0; 66629];
        reader.read_exact(&mut intro);
    }
    msg!("Sending solve.so");
    let mut line = String::new();
    writeln!(stream, "{}", solve_id)?;
    reader.read_line(&mut line)?;
    writeln!(stream, "{}", so_data.len())?;
    stream.write_all(&so_data)?;
    msg!("Successfully send solve.so !");
    reader.read_line(&mut line)?;
    reader.read_line(&mut line)?;
    
    
    let program_id = Pubkey::from_str(&get_line(&mut reader)?)?;
    msg!("program pubkey: {}", program_id);
    let user = Pubkey::from_str(&get_line(&mut reader)?)?;
    msg!("user pubkey: {}", user);
    let (config_addr_2, config_bump_2) =
        Pubkey::find_program_address(&["CONFIG2".as_bytes()], &program_id);
    let (config_addr, config_bump) =
        Pubkey::find_program_address(&["CONFIG".as_bytes()], &program_id);
    let (vault_addr, vault_bump) = Pubkey::find_program_address(&["VAULT".as_bytes()], &program_id);


    let data: &[u8; 11] = b"placeholder";  
    let metas: Vec<AccountMeta> = vec![
            AccountMeta::new(program_id, false),
            AccountMeta::new(user, true),
            AccountMeta::new(config_addr, false),
            AccountMeta::new(vault_addr, false),
            AccountMeta::new_readonly(system_program::id(), false),
            ];
            
    reader.read_line(&mut line)?;
    writeln!(stream, "{}", metas.len())?;
    for meta in metas {
        let mut meta_str = String::new();
        meta_str.push('m');
        if meta.is_writable {
            meta_str.push('w');
        }
        if meta.is_signer {
            meta_str.push('s');
        }
        meta_str.push(' ');
        meta_str.push_str(&meta.pubkey.to_string());

        writeln!(stream, "{}", meta_str)?;
        stream.flush()?;
    }

    reader.read_line(&mut line)?;
    writeln!(stream, "{}", data.len())?;
    stream.write_all(data)?;
    stream.flush()?;

    line.clear();
    while reader.read_line(&mut line)? != 0 {
        print!("{}", line);
        line.clear();
    }

    Ok(())
}