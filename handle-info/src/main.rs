use clap::{App, Arg};
use ntapi::ntexapi::{NtQuerySystemInformation, PSYSTEM_HANDLE_INFORMATION, SYSTEM_HANDLE_TABLE_ENTRY_INFO};
use prettytable::{format, Table};
use std::{
    env::args,
    process::exit,
    slice::from_raw_parts_mut,
};
use winapi::{
    shared::{
        ntdef::ULONG,
        ntstatus::STATUS_INFO_LENGTH_MISMATCH,
    },
    um::{
        heapapi::{GetProcessHeap, HeapAlloc, HeapReAlloc},
        winnt::HEAP_ZERO_MEMORY,
    }
};

#[macro_use] extern crate prettytable;

fn handle_type(h_type: u8) -> String {
    /*
    Types yet to be defined:
    Standard
    DebugObject
    EventPair
    LsaAccount
    LsaPolicy
    LsaSecret
    LsaTrusted
    Process60
    Profile
    SamAlias
    SamDomain
    SamGroup
    SamServer
    SamUser
    Service
    SCManager
    Thread60
    TmEn
    TmTx
    TokenDefault
    Type
    Wbem
    Rdp
    */
    let ret = match h_type {
        0x03 => "Directory",
        0x04 => "SymbolicLink",
        0x05 => "Token",
        0x06 => "Job",
        0x07 => "Process",
        0x08 => "Thread",
        0x09 => "Partition",
        0x0b => "IoCompletionReserve",
        0x10 => "Event",
        0x11 => "Mutant",
        0x13 => "Semaphore",
        0x14 => "Timer",
        0x15 => "IRTimer",
        0x17 => "KeyedEvent",
        0x18 => "WindowStation",
        0x19 => "Desktop",
        0x1a => "Composition",
        0x1b => "RawInputManager",
        0x1c => "CoreMessaging",
        0x1e => "TpWorkerFactory",
        0x23 => "IoCompletion",
        0x24 => "WaitCompletionPacket",
        0x25 => "File",
        0x26 => "TmTm",
        0x28 => "TmRm",
        0x2a => "Section",
        0x2b => "Session",
        0x2c => "Key",
        0x2e => "ALPC Port",
        0x2f => "EnergyTracker",
        0x30 => "PowerRequest",
        0x31 => "WmiGuid",
        0x32 => "EtwRegistration",
        0x34 => "EtwConsumer",
        0x37 => "PcwObject",
        0x38 => "FilterConnectionPort",
        0x39 => "FilterCommunicationPort",
        0x3b => "DxgkSharedResource",
        0x3d => "DxgkSharedSyncObject",
        0x3f => "DxgkDisplayManagerObject",
        0x43 => "Event",
        _ => return format!("{:#x} UnknownType", h_type),
    };
    ret.to_string()
}

fn granted_access(access: ULONG) -> String {
    // ACCESS TYPES
    match access {
        // Standard access types
        0x00010000 => return "DELETE".to_string(),
        0x00020000 => return "READ_CONTROL".to_string(),
        0x00040000 => return "WRITE_DAC".to_string(),
        0x00080000 => return "WRITE_OWNER".to_string(),
        0x00100000 => return "SYNCHRONIZE".to_string(),
        0x000F0000 => return "STANDARD_RIGHTS_REQUIRED".to_string(),
        0x001F0000 => return "STANDARD_RIGHTS_ALL".to_string(),
        0x0000FFFF => return "SPECIFIC_RIGHTS_ALL".to_string(),
        // AccessSystemAcl access type
        0x01000000 => return "ACCESS_SYSTEM_SECURITY".to_string(),
        // MaximumAllowed access type
        0x02000000 => return "MAXIMUM_ALLOWED".to_string(),
        //  These are the generic rights.
        0x80000000 => return "GENERIC_READ".to_string(),
        0x40000000 => return "GENERIC_WRITE".to_string(),
        0x20000000 => return "GENERIC_EXECUTE".to_string(),
        0x10000000 => return "GENERIC_ALL".to_string(),
        _ => return format!("{:#x}", access),
    }
}

fn get_handles(pid: u32) {
    // allocate buffer
    let mut bufsize: usize = 0x4000;
    let mut buf = unsafe { HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        bufsize,
    )};

    // Allocate the correct size buffer for NtQuerySystemInformation
    while unsafe { NtQuerySystemInformation(
        16 as _,
        buf,
        bufsize as _,
        0 as _,
    )} == STATUS_INFO_LENGTH_MISMATCH {
        bufsize = bufsize * 2;
        buf = unsafe { HeapReAlloc(
            GetProcessHeap(),
            0 as _,
            buf,
            bufsize,
        )};
    }

    // Obtain number of handles and struct containing handle information
    let handle_list_ptr = buf as PSYSTEM_HANDLE_INFORMATION;
    let handle_list_tmp = unsafe{ *handle_list_ptr };
    let num_handles = handle_list_tmp.NumberOfHandles as usize;
    let handle_list: &mut [SYSTEM_HANDLE_TABLE_ENTRY_INFO] = unsafe { from_raw_parts_mut(handle_list_ptr.offset(4) as _, num_handles) };

    // iterate over handles
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER);
    table.add_row(row!["PID", "ObjectTypeIndex", "HandleValue", "Object", "GrantedAccess", "CreatorBackTraceIndex", "HandleAttributes"]);
    for i in 0..num_handles {
        let current_handle = handle_list[i as usize];
        if (pid != 0) && !(current_handle.UniqueProcessId as u32 == pid) {
            continue;
        }
        table.add_row(row![
            current_handle.UniqueProcessId,
            handle_type(current_handle.ObjectTypeIndex),
            format!("{:#x}", current_handle.HandleValue),
            format!("{:?}", current_handle.Object),
            granted_access(current_handle.GrantedAccess),
            format!("{:#x}", current_handle.CreatorBackTraceIndex),
            format!("{:#x}", current_handle.HandleAttributes),
        ]);
    }
    // print to stdout
    table.printstd();
    println!();
}

fn main() {
    // parse args
    let mut app = App::new("handle-info")
        .version("0.1.0")
        .author("written by postrequest")
        .about("provide handle information")
        .arg(
            Arg::with_name("pid")
            .long("pid")
            .short("p")
            .takes_value(true)
            .required(false)
        )
    ;
    if args().count() < 1 {
        app.print_help().expect("Error loading help");
        exit(1);
    }
    let matches = app.get_matches();
    let pid = if matches.is_present("pid") {
        let pid_str = matches.value_of("pid").unwrap();
        let pid = match pid_str.parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => 0,
        };
        pid
    } else {
        0
    };
    get_handles(pid);
}
