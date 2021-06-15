use clap::{App, Arg};
use ntapi::{
    ntapi_base::CLIENT_ID,
    ntexapi::{
        NtQuerySystemInformation,
        PSYSTEM_HANDLE_INFORMATION,
        SYSTEM_HANDLE_TABLE_ENTRY_INFO
    },
    ntobapi::{
        NtDuplicateObject,
        NtQueryObject,
        POBJECT_NAME_INFORMATION,
    },
    ntpsapi::NtOpenProcess,
};
use prettytable::{format, Table};
use std::{
    env::args,
    ffi::OsStr,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    process::exit,
    slice::from_raw_parts_mut,
};
use winapi::{
    shared::{
        ntdef::{
            HANDLE, 
            LUID, 
            NT_SUCCESS,
            OBJECT_ATTRIBUTES, 
            ULONG,
        },
        ntstatus::{
            STATUS_BUFFER_OVERFLOW,
            STATUS_BUFFER_TOO_SMALL,
            STATUS_INFO_LENGTH_MISMATCH,
        },
        winerror::ERROR_NOT_ALL_ASSIGNED,
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        heapapi::{GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc},
        processthreadsapi::{GetCurrentProcess, GetCurrentProcessId, OpenProcessToken},
        securitybaseapi::AdjustTokenPrivileges,
        winbase::LookupPrivilegeValueW,
        winnt::{
            HEAP_ZERO_MEMORY,
            LUID_AND_ATTRIBUTES, 
            PROCESS_DUP_HANDLE,
            SE_DEBUG_NAME,
            SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES,
            TOKEN_PRIVILEGES,
            TOKEN_QUERY,
        },
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

pub fn get_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn enable_sedebug() -> bool {
    // Obtain token handle
    let mut h_token: HANDLE = 0 as _;
    let _ = unsafe { OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut h_token,
    )};

    // Required privilege
    let privs = LUID_AND_ATTRIBUTES {
        Luid: LUID { 
            LowPart: 0, 
            HighPart: 0,
        },
        Attributes: SE_PRIVILEGE_ENABLED,
    };
    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [privs ;1],
    };
    let _ = unsafe { LookupPrivilegeValueW(
        0 as _,
        get_wide(SE_DEBUG_NAME).as_mut_ptr(),
        &mut tp.Privileges[0].Luid,
    )};

    // Enable the privilege
    let _ = unsafe { AdjustTokenPrivileges(
        h_token,
        false as _,
        &mut tp,
        size_of::<TOKEN_PRIVILEGES>() as _,
        0 as _,
        0 as _,
    )};

    // Check if privilege was enabled
    if unsafe{ GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
        println!("{:?} not assigned: Please run as Administrator", SE_DEBUG_NAME);
        return false
    }
    let _ = unsafe { CloseHandle(h_token) };

    return true
}

fn handle_name(pid: u32, wanted_handle: HANDLE) -> String {
    let mut dup_handle: HANDLE = 0 as _;
    let mut handle: HANDLE = 0 as _;

    // Obtain remote HANDLE
    if pid == unsafe { GetCurrentProcessId() } {
        handle = unsafe { GetCurrentProcess() };
        dup_handle = handle;
    } else {
        // use NtOpenProcess because OpenProcess does not allow HANDLEs for SYSTEM processes
        let mut oa = OBJECT_ATTRIBUTES{ 
            Length: 0 as _,
            RootDirectory: 0 as _,
            ObjectName: 0 as _,
            Attributes: 0 as _,
            SecurityDescriptor: 0 as _,
            SecurityQualityOfService: 0 as _,
        };
        let mut cid = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: 0 as _,
        };
        let op_status = unsafe { NtOpenProcess(
            &mut handle,
            PROCESS_DUP_HANDLE,
            &mut oa,
            &mut cid,
        )};
        if !NT_SUCCESS(op_status) {
            return "".to_string()
        }
        let status = unsafe { NtDuplicateObject(
            handle,
            wanted_handle,
            GetCurrentProcess(),
            &mut dup_handle,
            0 as _,
            0 as _,
            0 as _,
        )};
        if !NT_SUCCESS(status) {
            return "".to_string()
        }
    }

    // allocate buffer
    let mut ret_len: ULONG = 0;
    let mut bufsize: usize = 0x1000;
    let mut buf = unsafe { HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        bufsize,
    )};
    // Obtain OBJECT_NAME_INFORMATION
    loop {
        let status = unsafe { NtQueryObject(
            dup_handle,
            1,
            buf,
            bufsize as _,
            &mut ret_len,
        )};
        if status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH {
            bufsize = bufsize * 2;
            buf = unsafe { HeapReAlloc(
                GetProcessHeap(),
                0 as _,
                buf,
                bufsize,
            )};
        } else {
            if !NT_SUCCESS(status) {
                return "".to_string()
            }
            break;
        }
    }

    // convert UNICODE_STRING to String and return
    let p_obi = buf as POBJECT_NAME_INFORMATION;
    let obi = unsafe { *p_obi };
    let unicode_str: &[u16] = unsafe {
        from_raw_parts_mut(obi.Name.Buffer, obi.Name.MaximumLength as _)
    };
    let name = String::from_utf16_lossy(unicode_str);
    let _ = unsafe { HeapFree(
        GetProcessHeap(),
        0 as _,
        buf,
    )};
    //if name.len() == 0 {
    //    return "NoData".to_string()
    //} 
    format!("{}", name)
    // processhacker/phlib/hndlinfo.c L1619 -> L161 basic || L363 name
}

fn get_handles(pid: u32, filter: String) {
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
    let handle_list: &mut [SYSTEM_HANDLE_TABLE_ENTRY_INFO] = unsafe { 
        from_raw_parts_mut(handle_list_ptr.offset(4) as _, num_handles) 
    };

    // iterate over handles
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER);
    if pid != 0 {
        table.add_row(row!["PID", "ObjectTypeIndex", "HandleValue", "HandleName", "Object", "GrantedAccess", "CreatorBackTraceIndex", "HandleAttributes"]);
    } else {
        table.add_row(row!["PID", "ObjectTypeIndex", "HandleValue", "Object", "GrantedAccess", "CreatorBackTraceIndex", "HandleAttributes"]);
    }
    for i in 0..num_handles {
        let current_handle = handle_list[i as usize];
        // check for PID
        if (pid != 0) && !(current_handle.UniqueProcessId as u32 == pid) {
            continue;
        }
        // check for filter
        if (filter != "".to_string()) && (handle_type(current_handle.ObjectTypeIndex) != filter) {
            continue;
        }
        // update table
        if pid != 0 {
            table.add_row(row![
                current_handle.UniqueProcessId,
                handle_type(current_handle.ObjectTypeIndex),
                format!("{:#x}", current_handle.HandleValue),
                handle_name(current_handle.UniqueProcessId as _, current_handle.HandleValue as _),
                format!("{:?}", current_handle.Object),
                granted_access(current_handle.GrantedAccess),
                format!("{:#x}", current_handle.CreatorBackTraceIndex),
                format!("{:#x}", current_handle.HandleAttributes),
            ]);
        } else {
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
        .arg(
            Arg::with_name("filter")
            .long("filter")
            .short("f")
            .takes_value(true)
            .required(false)
            .help("ALPC, Composition, CoreMessaging, Desktop, Directory, DxgkDisplayManagerObject, DxgkSharedResource, DxgkSharedSyncObject, EnergyTracker, EtwConsumer, EtwRegistration, Event, Event, File, FilterCommunicationPort, FilterConnectionPort, IoCompletion, IoCompletionReserve, IRTimer, Job, Key, KeyedEvent, Mutant, Partition, PcwObject, PowerRequest, Process, RawInputManager, Section, Semaphore, Session, SymbolicLink, Thread, Timer, TmRm, TmTm, Token, TpWorkerFactory, WaitCompletionPacket, WindowStation, WmiGuid")
        )
    ;
    if args().count() < 1 {
        app.print_help().expect("Error loading help");
        exit(1);
    }

    // parse args
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
    let filter = if matches.is_present("filter") {
        let pid_str = matches.value_of("filter").unwrap();
        pid_str.to_string()
    } else {
        "".to_string()
    };

    // Enable privs
    if !enable_sedebug() {
        return
    }

    get_handles(pid, filter);
}
