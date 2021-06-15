use winapi::{
    um::psapi::{
        EnumDeviceDrivers,
        GetDeviceDriverBaseNameW,
    },
    shared::minwindef::LPVOID,
};
use prettytable::{format, Table};

#[macro_use] extern crate prettytable;

fn main() {
    let mut lp_image_base_size: usize = 1024;
    let mut cb_needed: u32 = 0;
    let mut drivers: Vec<LPVOID> = vec![0 as _; lp_image_base_size];

    // Obtain driver list
    loop {
        let enum_ret = unsafe { EnumDeviceDrivers(
            drivers.as_mut_ptr() as _,
            lp_image_base_size as _,
            &mut cb_needed,
        )};

        // check return
        if enum_ret == 0 || (cb_needed as usize) < lp_image_base_size {
            lp_image_base_size = lp_image_base_size * 2;
            drivers = vec![0 as _; lp_image_base_size];
            continue;
        }
        break;
    }

    // remove null ref pointers
    drivers.retain(|&x| x != 0x0 as _);

    // list drivers
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER);
    table.add_row(row!["Driver", "Load Address"]);
    let name_size = 256;
    for i in 0..drivers.len() {
        let mut name = [0; 256];
        let _ = unsafe { GetDeviceDriverBaseNameW(
            drivers[i] as _, 
            &mut name[0], 
            name_size,
        )};
        table.add_row(row![
            String::from_utf16_lossy(&name[..name_size as usize]),
            format!("{:?}", drivers[i]),
        ]);
    }
    table.printstd();
    println!();
    println!("Total drivers loaded: {}", drivers.len());
}
