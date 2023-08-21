#![cfg(not(feature = "no-entrypoint"))]
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, system_program,
};

#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub enum TribunalInstruction {
    Initialize { config_bump: u8, vault_bump: u8 },
    Propose { proposal_id: u8, proposal_bump: u8 },
    Vote { proposal_id: u8, amount: u64 },
    Withdraw { amount: u64 },
}

#[repr(u8)]
#[derive(Debug, BorshSerialize, BorshDeserialize, PartialEq)]
pub enum Types {
    Config,
    Proposal,
    Vault,
}

#[repr(C)]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Config {
    pub discriminator: Types,
    pub admin: Pubkey,
    pub total_balance: u64,
}

#[repr(C)]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Proposal {
    pub discriminator: Types,
    pub creator: Pubkey,
    pub balance: u64,
    pub proposal_id: u8,
}

#[repr(C)]
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Vault {
    pub discriminator: Types,
}

pub const CONFIG_SIZE: usize = std::mem::size_of::<Config>();
pub const PROPOSAL_SIZE: usize = std::mem::size_of::<Proposal>();
pub const VAULT_SIZE: usize = std::mem::size_of::<Vault>();


entrypoint!(process_instruction);
fn process_instruction(
    solve_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let program = next_account_info(account_iter)?;
    let program_id = *program.key;
    let user = next_account_info(account_iter)?;
    let config = next_account_info(account_iter)?;
    let vault = next_account_info(account_iter)?;

    let (config_addr, config_bump) =
        Pubkey::find_program_address(&["CONFIG".as_bytes()], &program_id);
    let (vault_addr, vault_bump) =
        Pubkey::find_program_address(&["VAULT".as_bytes()], &program_id);
    let proposal_addrs: Vec<Pubkey> = (1..=5_u8)
        .map(|i| {
            Pubkey::find_program_address(&["PROPOSAL".as_bytes(), &i.to_be_bytes()], &program_id).0
        })
        .collect();

    msg!("Program {}", solve_id);
    msg!("solving program {:?}", program);
    msg!("user: {:?}", user);
    msg!("config: {:?}", config);
    msg!("vault: {:?}", vault);
    // for propo in proposal_addrs.clone() {
    //     let s = AccountMeta::new(propo);
    //     s.
    // }
    let (config_addr_2, config_bump_2) =
        Pubkey::find_program_address(&["CONFIG2".as_bytes()], &program_id);

    // create config
    invoke_signed(
        &system_instruction::create_account(
            &user.key,
            &config.key,
            Rent::minimum_balance(&Rent::default(), CONFIG_SIZE),//1224960
            CONFIG_SIZE as u64,
            &program_id,
        ),
        &[user.clone(), config.clone()],
        &[&[b"CONFIG", &[config_bump]]],
    )?;
    // save config data
    let config_data = Config {
        discriminator: Types::Config,
        admin: *user.key,
        total_balance: 0,
    };
    config_data
        .serialize(&mut &mut (*config.data).borrow_mut()[..])
        .unwrap();

    // msg!("Create new config");

    // Withdraw
    // invoke(
    //     &Instruction::new_with_borsh(
    //         *program.key,
    //         &TribunalInstruction::Withdraw {
    //             amount: 90_000_000_000, // 99 sol
    //         },
    //         vec![
    //             AccountMeta::new(*user.key, true),
    //             AccountMeta::new(*config.key, false),
    //             AccountMeta::new(*vault.key, false),
    //             AccountMeta::new_readonly(system_program::id(), false),
    //         ],
    //     ),
    //     &[user.clone(), config.clone()],
    // )?;
    msg!("done solving");

    Ok(())
}
