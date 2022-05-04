# Nulled Auth
A wrapper for nulled.to's updated authentication system implemented in rust

## Example
 ```rust
fn main() {
    let auth_key = String::from("auth_key");
    let program_id = String::from("program_id");
    let program_secret = String::from("program_secret");
    let minimum_likes = 0;
    let minimum_extra = nulled_auth::Ranks::Nova;
    let display_welcome = false;

    let authentication = nulled_auth::Authenticate::new(
        program_id,
        program_secret,
        minimum_likes,
        minimum_extra,
        display_welcome
    );
    
    let is_authenticated: (bool, String) = authentication.authenticate(auth_key).await;
    let success = is_authenticated.0;
    let message = is_authenticated.1; // Message can contain error message
}
 ```
