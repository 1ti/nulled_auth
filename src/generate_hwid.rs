use sha2::{Digest, Sha256};
use std::{env, process::Command};
use sysinfo::{DiskExt, System, SystemExt};
use whoami;
use winreg::enums::*;
use winreg::RegKey;

fn get_guid() -> String {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = match hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography") {
        Ok(reg_key) => reg_key,
        Err(_) => panic!("Failed to open key: SOFTWARE\\Microsoft\\Cryptography"),
    };
    let guid: String = match cur_ver.get_value("MachineGuid") {
        Ok(guid) => guid,
        Err(_) => panic!("Failed to get \"MachineGuid\""),
    };
    guid.to_uppercase()
}

fn get_disk_size() -> u64 {
    let mut sys = System::new_all();
    sys.refresh_all();
    for t_disk in sys.disks() {
        let c_disk = t_disk
            .mount_point()
            .to_str()
            .expect("Error whilst converting disk name to string!");
        if c_disk.contains("C:\\") {
            return t_disk.total_space();
        }
    }
    return 0;
}

fn get_uuid() -> String {
    let output = Command::new("cmd")
        .args(&["/C", "wmic csproduct get UUID"])
        .output()
        .expect("failed to execute process");
    let uuid = match String::from_utf8(output.stdout) {
        Ok(line) => String::from(line.split("UUID").nth(1).unwrap()),
        Err(_) => {
            println!("Failed to retrieve UUID from windows shell.");
            String::from("")
        }
    };
    uuid.chars()
        .filter(|c| c.is_alphanumeric() || c == &'-')
        .collect()
}

pub(crate) fn generate_hwid() -> Result<String, String> {
    let u_name = whoami::username();
    let c_name = whoami::hostname();
    let p_rev = match env::var("PROCESSOR_REVISION") {
        Ok(p_rev) => p_rev,
        Err(_) => return Err("PROCESSOR_REVISION may not be environment variable".to_owned()),
    };
    let disk: u64 = get_disk_size();
    let uuid: String = get_uuid();
    let guid: String = get_guid();
    let mut hasher = Sha256::new();
    hasher.update(format!(
        "{}{}{}{}{}{}",
        c_name, u_name, p_rev, disk, uuid, guid
    ));
    let hash = format!("{:x}", hasher.finalize()).to_uppercase();
    Ok(hash)
}
