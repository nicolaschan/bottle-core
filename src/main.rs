use bincode::{serialize, deserialize};
use colored::*;
use ed25519_dalek::{Keypair, Signature};
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use ron::{ser};
use serde::{Serialize, Deserialize};
use sha3::{Keccak256, Digest};
use std::convert::TryInto;
use std::io::{copy, Seek, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use rusqlite::params;
use x25519_dalek::{EphemeralSecret};

#[derive(Serialize, Deserialize, Debug)]
struct Metadata {
    end_of_chain: bool
}

#[derive(Serialize, Deserialize, Debug)]
struct MessageBody {
    parents: Vec<[u8;32]>,
    nonce: u64,
    content: [u8;32],
    metadata: Metadata
}

impl MessageBody {
    fn new(parents: Vec<&Message>, content: ContentHeader) -> Result<MessageBody, bincode::Error> {
        Ok(MessageBody {
            parents: parents.iter().try_fold(Vec::new(), |mut acc, p| -> Result<_, bincode::Error> {
                let p_ser = serialize(p)?;
                acc.push(Keccak256::new().chain(p_ser).result().into());
                Ok(acc)
            })?,
            nonce: rand::random::<u64>(),
            content: Keccak256::new().chain(&serialize(&content)?).result().into(),
            metadata: Metadata { end_of_chain: false },
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    body: MessageBody,
    sender: ed25519_dalek::PublicKey,
    signature: Signature
}

impl Message {
    fn new(parents: Vec<&Message>, content: ContentHeader, keypair: &Keypair) -> Result<Message, bincode::Error> {
        let body = MessageBody::new(parents, content)?;
        let body_ser = serialize(&body)?;
        Ok(Message {
            body: body,
            sender: keypair.public,
            signature: keypair.sign(&body_ser)
        })
    }
}

fn store_message<T: Serialize>(db: &rusqlite::Connection, message: &T) -> Result<(), Box<dyn std::error::Error>> {
    let serialized_message = serialize(message)?;
    let hashed_message: [u8;32] = Keccak256::new().chain(&serialized_message).result().into();
    db.execute("INSERT OR IGNORE INTO messages (hash, message) VALUES (?1, ?2)", params![hashed_message.to_vec(), serialized_message])?;
    Ok(())
}

fn store_content_body(db: &rusqlite::Connection, content_piece: &ContentBody) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = serialize(content_piece)?;
    let hashed: [u8;32] = Keccak256::new().chain(&serialized).result().into();
    db.execute("INSERT OR IGNORE INTO content_pieces (hash, piece, prev) VALUES (?1, ?2, ?3)", params![hashed.to_vec(), serialized, content_piece.prev.map(|p| p.to_vec()).unwrap_or(vec![])])?;
    Ok(())
}

fn get_content_body(db: &rusqlite::Connection, hash: [u8;32]) -> Result<Option<ContentBody>, Box<dyn std::error::Error>> {
    let mut stmt = db.prepare("SELECT piece FROM content_pieces WHERE hash = ?1")?;
    let mut rows = stmt.query(params![hash.to_vec()])?;
    let row = match rows.next() {
        Ok(Some(row)) => row,
        Ok(None) => return Ok(None),
        Err(e) => return Err(Box::new(e))
    };
    let value: &Vec<u8> = &row.get(0)?;
    Ok(Some(deserialize(value)?))
}

fn get_first_from_content_refs(db: &rusqlite::Connection, last: [u8;32]) -> Result<Option<[u8;32]>, Box<dyn std::error::Error>> {
    let mut stmt = db.prepare("SELECT first FROM content_refs WHERE last = ?1")?;
    let mut rows = stmt.query(params![last.to_vec()])?;
    let row = match rows.next() {
        Ok(Some(row)) => row,
        Ok(None) => return Ok(None),
        Err(e) => return Err(Box::new(e))
    };
    let value: &Vec<u8> = &row.get(0)?;
    let mut output = [0u8;32];
    let slice = &value[..output.len()];
    output.copy_from_slice(slice);
    Ok(Some(output))
}

fn lookup_message_local<'a, T: serde::de::DeserializeOwned>(db: &rusqlite::Connection, message_hash: [u8;32]) -> Result<Option<T>, Box<dyn std::error::Error>> {
    let mut stmt = db.prepare("SELECT message FROM messages WHERE hash = ?1")?;
    let mut rows = stmt.query(params![message_hash.to_vec()])?;
    let row = match rows.next() {
        Ok(Some(row)) => row,
        Ok(None) => return Ok(None),
        Err(e) => return Err(Box::new(e))
    };
    let value: &Vec<u8> = &row.get(0)?;
    Ok(Some(deserialize(value)?))
}

static CONTENT_CHUNK_SIZE: usize = 50000;
lazy_static! {
    static ref NOISE_PARAMS: snow::params::NoiseParams = "Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ContentHeaderPayload {
    size: u64,
    first: [u8;32],
    last: [u8;32]
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ContentHeader {
    payload: ContentHeaderPayload,
    pubkey: ed25519_dalek::PublicKey,
    signature: Signature
}

impl ContentHeader {
    fn new(first: ContentBody, last: ContentBody, keypair: &Keypair) -> ContentHeader {
        let payload = ContentHeaderPayload {
            size: last.depth,
            first: Keccak256::new().chain(&serialize(&first).unwrap()).result().into(),
            last: Keccak256::new().chain(&serialize(&last).unwrap()).result().into()
        };
        let signature = keypair.sign(&serialize(&payload).unwrap());
        ContentHeader {
            payload: payload,
            pubkey: keypair.public,
            signature: signature
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ContentBody {
    depth: u64,
    prev: Option<[u8;32]>,
    content: Vec<u8>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum ContentPiece {
    Body(ContentBody),
    Header(ContentHeader)
}

impl ContentBody {
    fn new(next: Option<&ContentBody>, content: Vec<u8>, keypair: &Keypair) -> Result<ContentBody, ()> {
        if content.len() > CONTENT_CHUNK_SIZE {
            return Err(());
        }
        let (depth, prev_hash) = match next {
            None => (0, None),
            Some(n) => (n.depth + 1, Some(Keccak256::new().chain(serialize(&n).unwrap()).result().into()))
        };
        Ok(ContentBody {
            depth: depth,
            prev: prev_hash,
            content: content
        })
    }
}

struct ContentStream<'a> {
    curr: ContentBody,
    progress: usize,
    db: &'a rusqlite::Connection
}

impl<'a> ContentStream<'a> {
    fn new(db: &rusqlite::Connection, content_hash: [u8;32]) -> Result<ContentStream, Box<dyn std::error::Error>> {
        let content_header = lookup_message_local::<ContentHeader>(&db, content_hash).unwrap().expect("could not find content header");
        let first_hash = content_header.payload.last;
        let curr = get_content_body(db, first_hash)?;
        Ok(ContentStream {
            curr: curr.expect("no entry exists at first content piece hash location"),
            progress: 0,
            db: db
        })
    }
}

impl<'a> Read for ContentStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        if self.curr.content.len() <= self.progress {
            let next_hash = self.curr.prev;
            match next_hash {
                None => return Ok(0),
                Some(next_hash) => {
                    match get_content_body(&self.db, next_hash).unwrap() {
                        None => return Ok(0),
                        Some(next) => { self.curr = next; self.progress = 0; }
                    };
                }
            }
        }
        // Read as much as possible from this chunk
        let len = std::cmp::min(self.curr.content.len() - self.progress, buf.len());
        buf[0..len].copy_from_slice(&self.curr.content[self.progress..self.progress + len]);
        self.progress = self.progress + len;
        Ok(len)
    }
}

fn reverse_read<T: Read>(mut input: T) -> std::fs::File {
    let mut tmp = tempfile::tempfile().unwrap();
    copy(&mut input, &mut tmp);
    return tmp;
}

struct ContentPieceChain<T: Seek> {
    input: T,
    keypair: Keypair,
    prev: ContentBody,
    current_pos: u64,
    end_pos: u64,
    started_from: u64,
    first: bool
}

impl ContentPieceChain<std::fs::File> {
    fn new<R: Read>(input: R, keypair: Keypair) -> ContentPieceChain<std::fs::File> {
        let body = ContentBody::new(None, Vec::new(), &keypair).unwrap();
        let mut tmp = reverse_read(input);
        let current = tmp.seek(std::io::SeekFrom::End(0)).unwrap();
        ContentPieceChain::<std::fs::File> {
            input: tmp,
            keypair: keypair,
            prev: body,
            current_pos: current,
            end_pos: current,
            started_from: current,
            first: true
        }
    }

}

impl ContentPieceChain<std::fs::File> {
    fn store(&mut self, db: &rusqlite::Connection) -> ([u8;32], ContentHeader) {
        let mut first: Option<ContentBody> = None;
        let mut last: Option<ContentBody> = Some(ContentBody::new(None, Vec::new(), &self.keypair).unwrap());
        let mut content_chain = &mut self.peekable();
        while let Some(content) = content_chain.next() {
            eprintln!("{}", format!("{:?}", content.depth).green());
            store_content_body(db, &content);
            if first.is_none() {
                first = Some(content.clone());
            }
            last = Some(content);
        }
        let header = ContentHeader::new(first.unwrap_or(ContentBody::new(None, Vec::new(), &self.keypair).unwrap()), last.unwrap(), &self.keypair);
        store_message(&db, &header);
        (Keccak256::new().chain(&serialize(&header).unwrap()).result().into(), header)
    }
}

impl Iterator for ContentPieceChain<std::fs::File> {
    type Item = ContentBody;
    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
            return Some(self.prev.clone());
        }
        if self.current_pos >= self.end_pos {
            if self.started_from == 0 {
                return None;
            }
            let next_pos = self.started_from - std::cmp::min(CONTENT_CHUNK_SIZE as u64, self.started_from);
            self.end_pos = self.started_from;
            self.started_from = next_pos;
            self.current_pos = next_pos;
            self.input.seek(std::io::SeekFrom::Start(self.current_pos));
        }
        let mut buf = vec![0u8;(self.end_pos - self.current_pos).try_into().unwrap()];
        let len = self.input.read(&mut buf).unwrap() as u64;
        self.current_pos = self.current_pos + len;
        if len == 0 {
            return None;
        }
        let content_piece = ContentBody::new(Some(&self.prev), buf.to_vec(), &self.keypair).unwrap();
        self.prev = content_piece.clone();
        Some(content_piece)
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ProtocolPairing {
    parent: [u8;32],
    child: [u8;32]
}

#[derive(Serialize, Deserialize, Debug)]
enum ContentProtocolMessage {
    Ask([u8;32]), // ask peer to send content with the hash
    Respond(ContentPiece), // peer responded with content
    // Discovery(TopicState, Signature), // if my topic state is newer, then I should reply with my newer discovery. if it's older, i should add the file listed to my wants
    ProtocolAsk([u8;32]), // according to some protocol's definition of "child", does the content with this hash have any children?
    ProtocolRespond(ProtocolPairing, Signature)
}

fn ask_for_content_body(mut s: &mut TcpStream, db: &rusqlite::Connection, mut transport: &mut snow::TransportState, hash: [u8;32]) -> bool {
    let mut buf = vec![0u8;65535];
    let mut current_hash = hash;
    let mut content = get_content_body(db, hash).unwrap();
    while let Some(c) = content {
        match c.prev {
            Some(prev) => {
                current_hash = prev;
                content = get_content_body(db, prev).unwrap();
            },
            None => return true
        };
    }
    let ask = ContentProtocolMessage::Ask(current_hash);
    let len = transport.write_message(&serialize(&ask).unwrap(), &mut buf).unwrap();
    send(&mut s, &buf[..len]);
    return false;
}

fn print_content(db: &rusqlite::Connection, hash: [u8;32]) {
    // let mut buf = Vec::new();
    let mut stdout = std::io::stdout();
    copy(&mut ContentStream::new(db, hash).unwrap(), &mut stdout);
    stdout.flush();
}

fn interact(mut s: &mut TcpStream, db: &rusqlite::Connection, mut transport: snow::TransportState) {
    let mut buf = vec![0u8;65535];
    let mut last_header: Option<[u8;32]> = None;
    while let Ok(message) = recv(&mut s) {
        let len = transport.read_message(&message, &mut buf).expect("not encrypted properly");
        let message = deserialize::<ContentProtocolMessage>(&buf[..len]).unwrap();
        match message {
            ContentProtocolMessage::Ask(hash) => {
                let content = get_content_body(&db, hash).unwrap();
                match content {
                    Some(content) => {
                        let respond = ContentProtocolMessage::Respond(ContentPiece::Body(content));
                        let len = transport.write_message(&serialize(&respond).unwrap(), &mut buf).unwrap();
                        send(&mut s, &buf[..len]);
                    },
                    None => {}
                }
            },
            ContentProtocolMessage::Respond(content) => {
                match content {
                    ContentPiece::Body(content) => {
                        store_content_body(&db, &content);

                        let hash: [u8;32] = Keccak256::new().chain(&serialize(&content).unwrap()).result().into();
                        eprintln!("{}", format!("{:x?}", hash).blue());
                        if let Some(prev) = content.prev {
                            if ask_for_content_body(&mut s, &db, &mut transport, prev) {
                                s.shutdown(std::net::Shutdown::Both);
                                print_content(db, last_header.unwrap());
                            }
                        } else {
                            s.shutdown(std::net::Shutdown::Both);
                            print_content(db, last_header.unwrap());
                        }
                    },
                    ContentPiece::Header(header) => {
                        // TODO: Verify signatures and such to make sure we want it
                        store_message(&db, &header);
                        last_header = Some(Keccak256::new().chain(&serialize(&header).unwrap()).result().into());
                        if ask_for_content_body(&mut s, &db, &mut transport, header.payload.last) {
                            s.shutdown(std::net::Shutdown::Both);
                            print_content(db, last_header.unwrap());
                        }
                    }
                }
            },
            ContentProtocolMessage::ProtocolAsk(hash) => {},
            ContentProtocolMessage::ProtocolRespond(pairing, sig) => {}
        };
    }
}

fn listen_thread(db: rusqlite::Connection, listener: TcpListener) {
    listener.set_nonblocking(false).unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let mut responder = snow::Builder::new(NOISE_PARAMS.clone()).build_responder().unwrap();
                let mut buf = vec![0u8;65535];

                let first_message = recv(&mut s).unwrap();
                responder.read_message(&first_message, &mut buf);
                let len = responder.write_message(&[0u8;0], &mut buf).unwrap();
                send(&mut s, &buf[..len]);

                let mut responder = responder.into_transport_mode().unwrap();
                // listener.set_nonblocking(true).unwrap();
                interact(&mut s, &db, responder);
            },
            _ => {}
        }
    }
}

fn client_thread(db: &rusqlite::Connection, other_ip: &String, protocol_message: &ContentProtocolMessage) {
    match TcpStream::connect(other_ip) {
        Ok(mut s) => {
            let mut buf = vec![0u8;65535];
            let mut sender = snow::Builder::new(NOISE_PARAMS.clone()).build_initiator().unwrap();
            let len = sender.write_message(&[], &mut buf).unwrap();
            send(&mut s, &buf[..len]);

            let response = recv(&mut s).unwrap();
            sender.read_message(&response, &mut buf).unwrap();
            let mut sender = sender.into_transport_mode().unwrap();

            let len = sender.write_message(&serialize(&protocol_message).unwrap(), &mut buf).unwrap();
            send(&mut s, &buf[..len]);
            // s.set_nonblocking(true).unwrap();
            interact(&mut s, &db, sender);
        },
        Err(_) => { eprintln!("{}", "connection refused".red()); }
    };
}

fn recv(stream: &mut TcpStream) -> Result<Vec<u8>, u8> {
    let mut length_buf = [0u8;2];
    stream.read_exact(&mut length_buf);
    let length = ((length_buf[0] as usize) << 8) + (length_buf[1] as usize);
    if length == 0 {
        stream.shutdown(std::net::Shutdown::Both);
        return Err(1);
    }
    let mut data = vec![0u8;length];
    stream.read_exact(&mut data);
    Ok(data)
}
fn send(stream: &mut TcpStream, data: &[u8]) -> Result<(), u8> {
    stream.write_all(&[(data.len() >> 8) as u8, (data.len() & 0xff) as u8]);
    stream.write_all(data);
    Ok(())
}

struct FluxductInterface {
    db: rusqlite::Connection,
    peers: Vec<String>
}

fn store_content_reference(db: &rusqlite::Connection, last: &ContentPiece, first: &ContentPiece) {
    let serialized_last = serialize(last).unwrap();
    let serialized_first = serialize(first).unwrap();
    let hashed_last: [u8;32] = Keccak256::new().chain(&serialized_last).result().into();
    let hashed_first: [u8;32] = Keccak256::new().chain(&serialized_first).result().into();
    db.execute("INSERT OR IGNORE INTO content_refs (last, first) VALUES (?1, ?2)", params![hashed_last.to_vec(), hashed_first.to_vec()]).unwrap();
}

impl FluxductInterface {
    pub fn new(db_path: &std::path::Path, listener: TcpListener) -> FluxductInterface {
        let db = rusqlite::Connection::open(db_path).unwrap();
        let thread_db = rusqlite::Connection::open(db_path).unwrap();
        let thread_handler = std::thread::spawn(|| listen_thread(thread_db, listener));
        db.execute("CREATE TABLE IF NOT EXISTS messages (hash BLOB PRIMARY KEY, message BLOB)", rusqlite::NO_PARAMS).unwrap();
        db.execute("CREATE TABLE IF NOT EXISTS content_refs (last BLOB PRIMARY KEY, first BLOB)", rusqlite::NO_PARAMS).unwrap();
        db.execute("CREATE TABLE IF NOT EXISTS content_pieces (hash BLOB PRIMARY KEY, piece BLOB, prev BLOB)", rusqlite::NO_PARAMS).unwrap();
        db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, data BLOB)", rusqlite::NO_PARAMS).unwrap();
        FluxductInterface {
            db: db,
            peers: Vec::new()
        }
    }

    // Append a message to the DAG, create content for its message body, and update our references to the branch heads. We will notify peers of this new branch head.
    pub fn send_message<T: Read>(&mut self, parents: Vec<&Message>, content: T) -> Result<Message, bincode::Error> {
        let mut first: Option<ContentPiece> = None;
        let mut last: Option<ContentPiece> = None;
        let mut content_chain = ContentPieceChain::new(content, get_keypair(&self.db).unwrap());
        let (_, content_header) = content_chain.store(&self.db);

        let message = Message::new(parents, content_header.clone(), &get_keypair(&self.db).unwrap())?;
        /*
        let serialized = serialize(&message).unwrap();
        let mut message_content_chain = ContentPieceChain::new(serialized.as_slice(), get_keypair(&self.db).unwrap());
        let (_, header) = message_content_chain.store(&self.db);
        store_message(&self.db, &message);
        */

        let protocol_message = ContentProtocolMessage::Respond(ContentPiece::Header(content_header));
        for peer in self.peers.iter() {
            client_thread(&self.db, peer, &protocol_message);
        }
        Ok(message)
    }

    pub fn add_peer(&mut self, address: String) {
        self.peers.push(address)
    }

    // Get the children of a message in the DAG
    pub fn get_children(&mut self, parent: Message) -> Result<Vec<Message>, ()> {
        Ok(Vec::new())
    }

    // Get the parents of a message in the DAG
    pub fn get_parents(&mut self, child: Message) -> Result<Vec<Message>, ()> {
        Ok(Vec::new())
    }

    // Request content to be downloaded by adding it to our list of wants and periodically ask peers for the things we want.
    pub fn request_content(&mut self, content_hash: [u8;32]) -> Result<(), ()> {
        Ok(())
    }

    // Read from content locally. If the content is not available locally (has not yet been downloaded), then this will return an Error and you should call `request_content()`.
    pub fn get_content_stream(&mut self, content_hash: [u8;32]) -> Result<ContentStream, Box<dyn std::error::Error>> {
        ContentStream::new(&self.db, content_hash)
    }

    // Get the content as a string. This is not a good idea if the content is very log.
    pub fn get_content_string(&mut self, content_hash: [u8;32]) -> Result<String, Box<dyn std::error::Error>> {
        let mut content = Vec::new();
        copy(&mut self.get_content_stream(content_hash)?, &mut content);
        Ok(String::from_utf8(content)?)
    }
}

fn create_keypair(db: &rusqlite::Connection) -> Result<Keypair, std::boxed::Box<dyn std::error::Error>> {
    let mut csprng = OsRng::new().unwrap();
    let keypair = Keypair::generate(&mut csprng);
    db.execute("INSERT INTO settings (key, data) VALUES (?1, ?2)", params!["keypair", keypair.to_bytes().to_vec()])?;
    Ok(keypair)
}

fn get_keypair(db: &rusqlite::Connection) -> Result<Keypair, std::boxed::Box<dyn std::error::Error>> {
    let mut stmt = db.prepare("SELECT data FROM settings WHERE key = 'keypair'")?;
    let mut rows = stmt.query(rusqlite::NO_PARAMS)?;
    let row = match rows.next() {
        Ok(Some(row)) => row,
        Ok(None) => return create_keypair(db),
        Err(e) => return Err(Box::new(e))
    };
    let value: &Vec<u8> = &row.get(0)?;
    Ok(Keypair::from_bytes(value).unwrap())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // println!("args: {:?}", args);

    let my_ip = format!("0.0.0.0:{}", args.get(1).unwrap_or(&"8080".to_string()));
    let listener = TcpListener::bind(my_ip).unwrap();
    let mut fluxduct = FluxductInterface::new(&std::path::Path::new(args.get(3).unwrap_or(&"fluxduct.db".to_string())), listener);

    let peer = format!("{}", args.get(2).unwrap_or(&"0.0.0.0:8081".to_string()));
    fluxduct.add_peer(peer);

    let stdin = std::io::stdin();
    fluxduct.send_message(Vec::new(), stdin.lock());
    /*
    for line in stdin.lock().lines() {
        fluxduct.send_message(Vec::new(), (line.unwrap() + "\n").as_bytes());
    }*/
}
