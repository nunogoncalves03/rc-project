# Auction System

### To compile both the `server` and the `user`:  
- Make sure you're at the **root** of the project and have `g++` that supports `C++17`  
- Run `make`
- Two executables were created at your working directory: `as` (server) and `client` (user)  

### To run the server:
run `./as [-p ASport] [-v]`:
- `-p` is the port where the server accepts requests (defaults to `58058`)  
- `-v` to run the server in verbose mode (incoming requests and sent responses are logged to the terminal) 

**Note**: all database files will be stored in `./DATABASE/`, which will be automatically created  

### To run the user:
run `./client [-n ASIP] [-p ASport]`:
- `-n` is the hostname or IP address of the AS (defaults to `localhost`)
- `-p` is the port where the AS accepts requests (defaults to `58058`)  

**Note**: all downloaded assets will be stored in `./ASSETS/`, which will be automatically created  

### To reset the auction database:
run `rm -rf DATABASE/`
