use reqwest::Client;
use reqwest::Response;
use serde::{self, Deserialize};

#[derive(Debug)]
pub enum Ranks {
    Nova = 1338,
    Aqua = 1337,
    VIP = 9999,
    None = 0,
}

#[derive(Deserialize)]
struct FirstAuthRequest {
    status: bool,
    data: FirstAuthData,
}

#[derive(Deserialize)]
struct FirstAuthData {
    message: String,
}

#[derive(Deserialize)]
struct SecondAuthRequest {
    #[serde(rename = "status")]
    _status: bool,
    data: SecondAuthData,
}

#[derive(Deserialize)]
struct SecondAuthData {
    #[serde(rename = "hash")]
    _hash: String,
    #[serde(rename = "mid")]
    _mid: String,
    name: String,
    #[serde(rename = "Likes")]
    likes: String,
    #[serde(rename = "groups")]
    _groups: Vec<String>,
    extra: u32,
    #[serde(rename = "message")]
    _message: String,
}

pub struct Authenticate {
    pub program_id: String,
    pub program_secret: String,
    pub minimum_likes: u32,
    pub minimum_extra: Ranks,
    pub display_welcome: bool,
}

impl Authenticate {
    pub fn new(
        program_id: String,
        program_secret: String,
        minimum_likes: u32,
        minimum_extra: Ranks,
        display_welcome: bool,
    ) -> Self {
        Self {
            program_id,
            program_secret,
            minimum_likes,
            minimum_extra,
            display_welcome,
        }
    }

    async fn send_request(&self, request_body: String) -> Result<Response, String> {
        let client = Client::new();
        match client
            .post("https://www.nulled.to/authkeys.php")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("User-Agent", "IPRange/0.1.0")
            .header("Connection", "keep-alive")
            .body(request_body)
            .send()
            .await
        {
            Ok(response) => return Ok(response),
            Err(_) => {
                return Err(String::from(
                    "Could not send request to nulled auth servers",
                ))
            }
        }
    }

    /// Authenticates a nulled user with a given authentication key
    ///
    /// # Examples
    ///
    /// ```
    /// use nulled_auth::{Authenticate, Ranks}
    /// fn main() {
    ///     let auth_key = String::from("auth_key");
    ///     let program_id = String::from("program_id");
    ///     let program_secret = String::from("program_secret");
    ///     let minimum_likes = 0;
    ///     let minimum_extra = Ranks::Nova;
    ///     let display_welcome = false;
    ///
    ///     let authentication = Authenticate::new(
    ///         program_id,
    ///         program_secret,
    ///         minimum_likes,
    ///         minimum_extra,
    ///         display_welcome
    ///     );
    ///
    ///     let is_authenticated: (bool, String) = authentication.authenticate(auth_key).await?;
    ///     let success = is_authenticated.0;
    ///     let message = is_authenticated.1; // Message can contain error message
    /// }
    /// ```

    pub async fn authenticate(&self, auth_key: String) -> (bool, String) {
        let auth_key = auth_key;
        let hwid = match generate_hwid::generate_hwid() {
            Ok(hwid) => hwid,
            Err(err) => return (false, err),
        };
        let program_id = &self.program_id;
        let register_body = format!(
            "register=1&key={}&hwid={}&program_id={}",
            auth_key, hwid, program_id
        );
        let validate_body = format!(
            "validate=1&key={}&hwid={}&program_id={}",
            auth_key, hwid, program_id
        );
        // First Request
        match self.send_request(register_body).await {
            Ok(response) => {
                let json = match response.json::<FirstAuthRequest>().await {
                    Ok(json) => json,
                    Err(_) => {
                        return (
                            false,
                            "Failed to deserialize first json response".to_owned(),
                        );
                    }
                };

                let request_success = json.status;
                let request_message = json.data.message;

                if !request_success && !request_message.eq("Duplicate registry") {
                    return (request_success, request_message);
                }

                match self.send_request(validate_body).await {
                    Ok(response) => {
                        let json = match response.json::<SecondAuthRequest>().await {
                            Ok(json) => json,
                            Err(_) => {
                                return (
                                    false,
                                    "Failed to deserialize second json response".to_owned(),
                                );
                            }
                        };

                        let data = json.data;

                        let name = data.name;
                        let likes = data.likes.parse::<u32>().unwrap();
                        let extra = data.extra;

                        if likes < self.minimum_likes {
                            return (false, "Insufficient amount of likes".to_owned());
                        }

                        if !&self.has_rank_or_greater(extra) {
                            return (
                                false,
                                "Current rank is lower than specified rank".to_owned(),
                            );
                        }

                        if self.display_welcome {
                            println!("Welcome {}!", name);
                        }
                        return (true, format!("Authenticated user: {} successfully", "name"));
                    }
                    Err(err) => return (false, err),
                }
            }

            Err(err) => return (false, err),
        };
    }

    fn has_rank_or_greater(&self, rank: u32) -> bool {
        let mut rank_value = match &self.minimum_extra {
            Ranks::Nova => Ranks::Nova as u32,
            Ranks::Aqua => Ranks::Aqua as u32,
            Ranks::VIP => Ranks::VIP as u32,
            Ranks::None => Ranks::None as u32,
        };

        if rank_value > 2000 {
            rank_value = 1336;
        }
        rank >= rank_value
    }
}

mod generate_hwid {
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
}
