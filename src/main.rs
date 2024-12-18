use libc;
use rustls::{
    client::{
        danger::HandshakeSignatureValid, danger::ServerCertVerified, danger::ServerCertVerifier,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConnection, DigitallySignedStruct, Error, SignatureScheme, StreamOwned,
};
use std::fs::File;
use std::io;
use std::io::Write;
use std::net::TcpStream;
use std::os::raw::{c_int, c_void};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

const AUTH_HEADER: &str = "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcmFuZ29kYiIsInNlcnZlcl9pZCI6ImZvbyJ9.Qr2vX5EvcW64IUvQfoiUPmPKhRydYitbWE4_4yUQUVU";

fn enable_tcp_keepalive(fd: c_int, idle: u32, interval: u32, count: u32) -> std::io::Result<()> {
    use libc::{
        setsockopt, IPPROTO_TCP, SOL_SOCKET, SO_KEEPALIVE, TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL,
    };

    unsafe {
        // Enable SO_KEEPALIVE
        let keepalive: c_int = 1;
        if setsockopt(
            fd,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &keepalive as *const _ as *const c_void,
            std::mem::size_of_val(&keepalive) as _,
        ) != 0
        {
            eprintln!(
                "Error enabling SO_KEEPALIVE: {}",
                std::io::Error::last_os_error()
            );
            return Err(std::io::Error::last_os_error());
        }

        // Set TCP_KEEPIDLE (time before starting keepalive probes)
        if setsockopt(
            fd,
            IPPROTO_TCP,
            TCP_KEEPIDLE,
            &idle as *const _ as *const c_void,
            std::mem::size_of_val(&idle) as _,
        ) != 0
        {
            eprintln!(
                "Error enabling SO_KEEPIDLE: {}",
                std::io::Error::last_os_error()
            );
            return Err(std::io::Error::last_os_error());
        }

        // Set TCP_KEEPINTVL (interval between keepalive probes)
        if setsockopt(
            fd,
            IPPROTO_TCP,
            TCP_KEEPINTVL,
            &interval as *const _ as *const c_void,
            std::mem::size_of_val(&interval) as _,
        ) != 0
        {
            eprintln!(
                "Error enabling SO_KEEPINTVL: {}",
                std::io::Error::last_os_error()
            );
            return Err(std::io::Error::last_os_error());
        }

        // Set TCP_KEEPCNT (number of keepalive probes before considering the connection dead)
        if setsockopt(
            fd,
            IPPROTO_TCP,
            TCP_KEEPCNT,
            &count as *const _ as *const c_void,
            std::mem::size_of_val(&count) as _,
        ) != 0
        {
            eprintln!(
                "Error enabling SO_KEEPCNT: {}",
                std::io::Error::last_os_error()
            );
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

fn dowork<S: std::io::Write + std::io::Read>(
    stream: &mut S,
    waiting_time: u64,
    query: bool,
    fd: i32,
) -> std::io::Result<()> {
    if !query {
        // Send a message
        let message = "GET /_api/version HTTP/1.1\r\n".to_string() + AUTH_HEADER + "\r\n\r\n";
        println!("Sending message: {}", message);
        stream.write_all(message.as_bytes())?;
    } else {
        let q = r#"{"query":"RETURN SLEEP(20)"}"#;
        let message = format!("POST /_api/cursor HTTP/1.1\r\n{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}\r\n", AUTH_HEADER, q.len(), q);
        println!("Sending message: {}", message);
        stream.write_all(message.as_bytes())?;
    }

    // Read the response
    let mut buffer = [0u8; 1024];
    let size = stream.read(&mut buffer)?;
    println!("Received: {}", String::from_utf8_lossy(&buffer[..size]));

    // Keep the connection open for a while
    println!(
        "Connection established. Sleeping for {} seconds...",
        waiting_time
    );
    for i in 0..waiting_time {
        std::thread::sleep(Duration::from_secs(1));
        println!("{} seconds passed.", i + 1);
        // Lets check the socket for an error:
        //let mut error: i32 = 0;
        //let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        //unsafe {
        //    libc::getsockopt(
        //        fd as c_int,
        //        libc::SOL_SOCKET,
        //        libc::SO_ERROR,
        //        &mut error as *mut _ as *mut libc::c_void,
        //        &mut len as *mut libc::socklen_t,
        //    );
        //}
        let buf = [0u8; 16];
        let len = unsafe {
            libc::recv(
                fd as c_int,
                buf.as_ptr() as *mut c_void,
                buf.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        let errno = unsafe { *libc::__errno_location() };
        println!(
            "Socket peek: {}, errno: {}, EAGAIN: {}, EWOULDBLOCK: {}",
            len,
            errno,
            libc::EAGAIN,
            libc::EWOULDBLOCK
        );
    }

    if !query {
        println!("Reading...");
        // Read whatever is there:
        let mut buffer = [0u8; 1024];
        let size = stream.read(&mut buffer)?;
        println!("Received: {}", String::from_utf8_lossy(&buffer[..size]));
    }

    // Send a message
    let message = "GET /_api/version HTTP/1.1\r\n".to_string() + AUTH_HEADER + "\r\n\r\n";
    println!("Sending message: {}", message);
    stream.write_all(message.as_bytes())?;

    // Read the response
    let mut buffer = [0u8; 1024];
    let size = stream.read(&mut buffer)?;
    println!("Received: {}", String::from_utf8_lossy(&buffer[..size]));

    println!("Closing connection.");
    Ok(())
}

#[derive(Debug)]
struct KeyLogger(File);

impl rustls::KeyLog for KeyLogger {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let mut file = &self.0;
        let mut buf: String = String::new();
        buf.push_str(label);
        buf.push_str(" ");
        buf.push_str(&hex::encode(client_random));
        buf.push_str(" ");
        buf.push_str(&hex::encode(secret));
        buf.push_str("\n");
        file.write_all(buf.as_bytes()).unwrap();
    }
}

// A custom verifier that disables certificate verification
#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn main() -> std::io::Result<()> {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() < 6 {
        eprintln!(
            "Usage: {} <host> <port> <keepalive> <waiting_time> <tls> <query>",
            args[0]
        );
        std::process::exit(1);
    }

    let host = args[1].clone();
    let port = args[2].parse::<u16>().unwrap();
    let keepalive = args[3].parse::<bool>().unwrap();
    let waiting_time = args[4].parse::<u64>().unwrap();
    let tls = args[5].parse::<bool>().unwrap();
    let query = args[6].parse::<bool>().unwrap();

    println!("Connecting to {}:{}...", host, port);

    // Open a TCP connection
    let mut tcp_stream: TcpStream = TcpStream::connect((host.as_str(), port))?;
    let fd = tcp_stream.as_raw_fd();

    // Optionally enable TCP_KEEPALIVE
    if keepalive {
        println!("Enabling TCP_KEEPALIVE...");
        enable_tcp_keepalive(fd, 1, 2, 3)?;
        println!("TCP_KEEPALIVE enabled.");
    }

    if !tls {
        dowork(&mut tcp_stream, waiting_time, query, fd)?;
    } else {
        let log_file = File::create("/tmp/sslkeys.log")?;
        let key_logger = Arc::new(KeyLogger(log_file));

        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.key_log = key_logger;
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification));

        let config_arc = Arc::new(config);
        let tls_connection = ClientConnection::new(config_arc, ServerName::try_from(host).unwrap())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut tls_stream = StreamOwned::new(tls_connection, tcp_stream);

        println!("TLS connection established.");
        dowork(&mut tls_stream, waiting_time, query, fd)?;
    }

    Ok(())
}
