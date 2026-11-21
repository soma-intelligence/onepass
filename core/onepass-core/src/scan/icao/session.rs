//! `IcaoSession`: the whole read of an eMRTD chip as a state machine that
//! hands out command APDUs and takes the chip's responses, so the NFC
//! transport (Core NFC on iOS, the Android reader) stays a dumb pipe.
//!
//! Order (ICAO 9303-11): read EF.CardAccess unprotected; PACE when it offers
//! a supported protocol, otherwise BAC (and one BAC attempt when PACE fails);
//! SELECT the eMRTD applet; read EF.COM, EF.SOD, DG1 and DG2 under secure
//! messaging in chunks of 0xE0 bytes; check that DG1 holds the scanned MRZ;
//! then passive authentication of EF.SOD against the master list.
//!
//! Never panics on a chip response: anything unexpected ends the session in
//! `Step::Failed`. Nothing here logs APDU bytes, keys or identity data, and
//! the files read sit in zeroize-on-drop buffers until the result is built.

use std::fmt;

use time::Date;
use zeroize::Zeroizing;

use super::IcaoError;
use super::bac::{BacExchange, derive_bac_keys};
use super::card_access::{parse_card_access, select_pace};
use super::dg::{Portrait, parse_com, parse_dg1, parse_dg2};
use super::master_list::MasterList;
use super::pace::{PaceCurve, PaceExchange, PaceRandom};
use super::passive_auth::{ChipStatus, verify_sod};
use super::sm::SecureChannel;
use crate::scan::apdu::{
    AID_EMRTD, Command, EF_CARD_ACCESS, EF_COM, EF_DG1, EF_DG2, EF_SOD, Response,
};
use crate::scan::mrz::Mrz;
use crate::scan::tlv;

/// What opens the chip. The CAN arrives in P2.
#[derive(Clone)]
pub enum AccessKey {
    Mrz(Mrz),
}

impl fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessKey(..)")
    }
}

/// The outcome of a read.
#[derive(Debug)]
pub struct ChipRead {
    /// The MRZ from DG1 (equal to the scanned one).
    pub mrz: Mrz,
    /// The DG2 portrait, when the chip has one that decodes.
    pub portrait: Option<Portrait>,
    pub status: ChipStatus,
    /// File ids read under secure messaging, in read order.
    pub progress_files: Vec<u16>,
}

/// What the transport does next. `Done` is large, but there is one `Step`
/// per APDU and it is moved, never stored in bulk: no box.
#[allow(clippy::large_enum_variant)]
pub enum Step {
    /// Send this command APDU and pass the answer to `on_response`.
    Send(Vec<u8>),
    Done(ChipRead),
    Failed(IcaoError),
}

impl fmt::Debug for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::Send(b) => write!(f, "Send({} bytes)", b.len()),
            Step::Done(r) => write!(f, "Done({:?})", r.status),
            Step::Failed(e) => write!(f, "Failed({e:?})"),
        }
    }
}

/// Fixed terminal randoms for a reproducible read (test builds only).
#[cfg(feature = "scan-test-rng")]
#[doc(hidden)]
#[derive(Clone)]
pub struct SessionRandom {
    pub bac_rnd_ifd: [u8; 8],
    pub bac_k_ifd: [u8; 16],
    /// PACE mapping and ephemeral scalars, the curve's field length.
    pub pace_map_sk: Vec<u8>,
    pub pace_eph_sk: Vec<u8>,
}

enum Rng {
    Os,
    #[cfg(feature = "scan-test-rng")]
    Fixed(SessionRandom),
}

/// Bytes asked for first, to learn a file's length: enough for a 3-byte
/// tag and the `83` length form.
const HEADER_LEN: usize = 8;
/// Bytes asked for per READ BINARY (B0). The wrapped answer must fit a
/// short response (256 bytes): 223 bytes pad to 224, so DO87 (4 header
/// bytes and 224) plus DO99 (4) plus DO8E (10) is 242 for 3DES and AES
/// alike, where 0xE0 would pad to 240 and overflow (258).
const CHUNK: usize = 0xDF;
/// File bytes per B1 read: the DO53 around them (53 81 n) must stay within
/// the same 223-byte plaintext budget as `CHUNK`.
const CHUNK_B1: usize = CHUNK - 3;
/// Largest file accepted (a DG2 is tens of kilobytes).
const MAX_FILE: usize = 1 << 20;
/// Largest EF.CardAccess read unprotected; bigger means BAC.
const MAX_CARD_ACCESS: usize = 4096;
/// Highest offset READ BINARY (B0) can carry in P1-P2.
const MAX_B0_OFFSET: usize = 0x7FFF;
/// 6Cxx / 61xx answers followed in a row before giving up.
const MAX_RETRIES: u8 = 4;

/// Size guesses for progress before a file's header is read.
const GUESS: [(u16, usize); 4] = [
    (EF_COM, 32),
    (EF_SOD, 2_000),
    (EF_DG1, 93),
    (EF_DG2, 15_000),
];

/// An elementary file being read, chunk by chunk.
struct FileRead {
    fid: u16,
    buf: Zeroizing<Vec<u8>>,
    total: Option<usize>,
    /// The last command asked with the odd INS (answer in DO53).
    odd: bool,
    asked: usize,
    max: usize,
}

impl FileRead {
    fn new(fid: u16) -> Self {
        FileRead {
            fid,
            buf: Zeroizing::new(Vec::new()),
            total: None,
            odd: false,
            asked: 0,
            max: if fid == EF_CARD_ACCESS {
                MAX_CARD_ACCESS
            } else {
                MAX_FILE
            },
        }
    }

    /// The next READ BINARY: B0 up to offset 0x7FFF, B1 with DO54 beyond.
    fn next_cmd(&mut self) -> Command {
        let off = self.buf.len();
        self.odd = off > MAX_B0_OFFSET;
        let chunk = if self.odd { CHUNK_B1 } else { CHUNK };
        let n = match self.total {
            None => HEADER_LEN,
            Some(t) => t.saturating_sub(off).min(chunk),
        };
        self.asked = n;
        if !self.odd {
            return Command::read_binary(off as u16, n as u8);
        }
        let off_bytes = if off <= 0xFFFF {
            (off as u16).to_be_bytes().to_vec()
        } else {
            (off as u32).to_be_bytes()[1..].to_vec()
        };
        // Le covers the DO53 header: 53 n (n < 0x80) or 53 81 n.
        let hdr = if n < 0x80 { 2 } else { 3 };
        Command {
            cla: 0x00,
            ins: 0xB1,
            p1: 0x00,
            p2: 0x00,
            data: tlv::encode(0x54, &off_bytes),
            le: Some((n + hdr) as u16),
        }
    }

    /// Take an answer (status already known to be 9000 or 6282). `true`
    /// when the whole file is in.
    fn feed(&mut self, r: &Response) -> Result<bool, IcaoError> {
        let chunk: &[u8] = if self.odd {
            let (el, _) =
                tlv::parse_one(&r.data).map_err(|_| IcaoError::Protocol("read-bad-do53"))?;
            if el.tag != 0x53 {
                return Err(IcaoError::Protocol("read-bad-do53"));
            }
            el.value
        } else {
            &r.data
        };
        if chunk.is_empty() || chunk.len() > self.asked {
            return Err(IcaoError::Protocol("read-bad-length"));
        }
        self.buf.extend_from_slice(chunk);
        if self.total.is_none() {
            let t = tlv::file_length(&self.buf).ok_or(IcaoError::Protocol("file-header"))?;
            if t > self.max {
                return Err(IcaoError::Protocol("file-too-large"));
            }
            self.total = Some(t);
        }
        let total = self.total.unwrap_or(0);
        if self.buf.len() >= total {
            self.buf.truncate(total);
            return Ok(true);
        }
        if r.sw == 0x6282 {
            return Err(IcaoError::Protocol("file-truncated"));
        }
        Ok(false)
    }
}

enum Phase {
    Idle,
    CardAccessSelect,
    CardAccessRead(FileRead),
    PaceSetAt(Box<PaceExchange>),
    PaceNonce(Box<PaceExchange>),
    PaceMap(Box<PaceExchange>),
    PaceKey(Box<PaceExchange>),
    PaceToken(Box<PaceExchange>),
    BacSelect,
    BacChallenge,
    BacAuth(Box<BacExchange>),
    AppletSelect,
    FileSelect(u16),
    FileRead(FileRead),
    Finished,
}

/// One chip read. Feed it the chip's answers until `Done` or `Failed`.
pub struct IcaoSession {
    seed: Zeroizing<String>,
    scanned: Mrz,
    master_list: MasterList,
    today: Date,
    rng: Rng,
    phase: Phase,
    channel: Option<SecureChannel>,
    /// The last command sent, unprotected, for a 6Cxx resend.
    last: Option<Command>,
    /// Data of 61xx answers waiting for the rest (GET RESPONSE).
    chained: Zeroizing<Vec<u8>>,
    retries: u8,
    /// LDS tags EF.COM lists.
    tags: Vec<u8>,
    sod: Zeroizing<Vec<u8>>,
    dg1: Zeroizing<Vec<u8>>,
    dg2: Option<Zeroizing<Vec<u8>>>,
    /// Sizes of the files read so far, by file id.
    sizes: Vec<(u16, usize)>,
    progress_files: Vec<u16>,
    progress: f32,
}

impl IcaoSession {
    pub fn new(key: AccessKey, master_list: MasterList, today: Date) -> Self {
        let AccessKey::Mrz(mrz) = key;
        IcaoSession {
            seed: Zeroizing::new(mrz.bac_key_seed_input()),
            scanned: mrz,
            master_list,
            today,
            rng: Rng::Os,
            phase: Phase::Idle,
            channel: None,
            last: None,
            chained: Zeroizing::new(Vec::new()),
            retries: 0,
            tags: Vec::new(),
            sod: Zeroizing::new(Vec::new()),
            dg1: Zeroizing::new(Vec::new()),
            dg2: None,
            sizes: Vec::new(),
            progress_files: Vec::new(),
            progress: 0.0,
        }
    }

    /// Replace the OS randoms with fixed ones (replayable test reads).
    #[cfg(feature = "scan-test-rng")]
    #[doc(hidden)]
    pub fn with_rng(mut self, rng: SessionRandom) -> Self {
        self.rng = Rng::Fixed(rng);
        self
    }

    /// The first command: SELECT EF.CardAccess on the master file.
    pub fn start(&mut self) -> Step {
        if !matches!(self.phase, Phase::Idle) {
            return self.fail(IcaoError::Protocol("session-started"));
        }
        self.phase = Phase::CardAccessSelect;
        self.send_plain(Command::select_ef(EF_CARD_ACCESS))
    }

    /// 0 to 1, in proportion to the bytes of the LDS files read.
    pub fn progress(&self) -> f32 {
        self.progress
    }

    /// The chip's answer to the last `Send`.
    pub fn on_response(&mut self, bytes: &[u8]) -> Step {
        if matches!(self.phase, Phase::Finished | Phase::Idle) {
            return Step::Failed(IcaoError::Protocol("session-not-running"));
        }
        let Ok(raw) = Response::parse(bytes) else {
            return self.fail(IcaoError::Protocol("short-response"));
        };
        let step = if let Some(ch) = self.channel.as_mut() {
            match ch.unwrap(&raw) {
                Ok(r) if r.sw >> 8 == 0x61 || r.sw >> 8 == 0x6C => self.fail(IcaoError::Chip(r.sw)),
                Ok(r) => self.dispatch(r),
                // The SSC has moved: the channel is dead.
                Err(e) => self.fail(e),
            }
        } else {
            self.plain(raw)
        };
        self.update_progress(&step);
        step
    }

    /// An unprotected answer: follow 6Cxx and 61xx, then dispatch.
    fn plain(&mut self, raw: Response) -> Step {
        let hi = raw.sw >> 8;
        if hi == 0x6C || hi == 0x61 {
            self.retries += 1;
            if self.retries > MAX_RETRIES {
                return self.fail(IcaoError::Chip(raw.sw));
            }
            let xx = raw.sw & 0xFF;
            let le = if xx == 0 { 256 } else { xx };
            if hi == 0x6C {
                let Some(mut cmd) = self.last.clone() else {
                    return self.fail(IcaoError::Chip(raw.sw));
                };
                if !raw.data.is_empty() {
                    return self.fail(IcaoError::Protocol("data-with-6cxx"));
                }
                cmd.le = Some(le);
                return self.send_plain_keep(cmd);
            }
            if self.chained.len() + raw.data.len() > MAX_FILE {
                return self.fail(IcaoError::Protocol("response-too-long"));
            }
            self.chained.extend_from_slice(&raw.data);
            let get_response = Command {
                cla: 0x00,
                ins: 0xC0,
                p1: 0x00,
                p2: 0x00,
                data: Vec::new(),
                le: Some(le),
            };
            return self.send_plain_keep(get_response);
        }
        self.retries = 0;
        let r = if self.chained.is_empty() {
            raw
        } else {
            let mut data = std::mem::take(&mut *self.chained);
            data.extend_from_slice(&raw.data);
            Response { data, sw: raw.sw }
        };
        self.dispatch(r)
    }

    fn dispatch(&mut self, r: Response) -> Step {
        match std::mem::replace(&mut self.phase, Phase::Finished) {
            Phase::Idle | Phase::Finished => self.fail(IcaoError::Protocol("session-not-running")),
            Phase::CardAccessSelect => {
                if !r.ok() {
                    // No EF.CardAccess (6A82) or refused: BAC.
                    return self.start_bac();
                }
                self.read_next(FileRead::new(EF_CARD_ACCESS))
            }
            Phase::CardAccessRead(mut f) => {
                if !r.ok() {
                    return self.start_bac();
                }
                match f.feed(&r) {
                    Ok(false) => self.read_next(f),
                    Ok(true) => self.after_card_access(&f.buf),
                    Err(_) => self.start_bac(),
                }
            }
            Phase::PaceSetAt(mut x) => match x.on_set_at(&r).and_then(|()| x.msg_nonce()) {
                Ok(cmd) => {
                    self.phase = Phase::PaceNonce(x);
                    self.send_plain(cmd)
                }
                Err(_) => self.start_bac(),
            },
            Phase::PaceNonce(mut x) => match x.on_nonce(&r) {
                Ok(cmd) => {
                    self.phase = Phase::PaceMap(x);
                    self.send_plain(cmd)
                }
                Err(_) => self.start_bac(),
            },
            Phase::PaceMap(mut x) => match x.on_map(&r) {
                Ok(cmd) => {
                    self.phase = Phase::PaceKey(x);
                    self.send_plain(cmd)
                }
                Err(_) => self.start_bac(),
            },
            Phase::PaceKey(mut x) => match x.on_key(&r) {
                Ok(cmd) => {
                    self.phase = Phase::PaceToken(x);
                    self.send_plain(cmd)
                }
                Err(_) => self.start_bac(),
            },
            Phase::PaceToken(x) => match x.on_token(&r) {
                Ok(ch) => {
                    self.channel = Some(ch);
                    self.phase = Phase::AppletSelect;
                    self.send_sm(Command::select_applet(&AID_EMRTD))
                }
                Err(_) => self.start_bac(),
            },
            Phase::BacSelect => {
                if !r.ok() {
                    return self.fail(IcaoError::Chip(r.sw));
                }
                self.phase = Phase::BacChallenge;
                self.send_plain(Command::get_challenge())
            }
            Phase::BacChallenge => {
                if !r.ok() {
                    return self.fail(IcaoError::Chip(r.sw));
                }
                let Ok(rnd_icc) = <[u8; 8]>::try_from(r.data.as_slice()) else {
                    return self.fail(IcaoError::Protocol("challenge-length"));
                };
                let (rnd_ifd, k_ifd) = match self.bac_random() {
                    Ok(v) => v,
                    Err(e) => return self.fail(e),
                };
                let keys = derive_bac_keys(&self.seed);
                let x = BacExchange::new(keys, rnd_icc, rnd_ifd, *k_ifd);
                let cmd = x.external_authenticate();
                self.phase = Phase::BacAuth(Box::new(x));
                self.send_plain(cmd)
            }
            Phase::BacAuth(x) => match x.finish(&r) {
                Ok(ch) => {
                    self.channel = Some(ch);
                    // The applet is already selected (before GET CHALLENGE).
                    self.select_file(EF_COM)
                }
                Err(e) => self.fail(e),
            },
            Phase::AppletSelect => {
                if !r.ok() {
                    return self.fail(IcaoError::Chip(r.sw));
                }
                self.select_file(EF_COM)
            }
            Phase::FileSelect(fid) => {
                if !r.ok() {
                    return match (fid, r.sw) {
                        // No EF.COM: assume DG1 and DG2.
                        (EF_COM, 0x6A82) => {
                            self.tags = vec![0x61, 0x75];
                            self.select_file(EF_SOD)
                        }
                        // No portrait: finish without it.
                        (EF_DG2, 0x6A82) => self.finish(),
                        _ => self.fail(IcaoError::Chip(r.sw)),
                    };
                }
                self.read_next(FileRead::new(fid))
            }
            Phase::FileRead(mut f) => {
                if !r.ok() {
                    return self.fail(IcaoError::Chip(r.sw));
                }
                match f.feed(&r) {
                    Ok(false) => self.read_next(f),
                    Ok(true) => self.file_done(f),
                    Err(e) => self.fail(e),
                }
            }
        }
    }

    /// EF.CardAccess read: PACE when it offers a supported protocol.
    fn after_card_access(&mut self, b: &[u8]) -> Step {
        let Ok(infos) = parse_card_access(b) else {
            return self.start_bac();
        };
        let Some(info) = select_pace(&infos) else {
            return self.start_bac();
        };
        let mut ids: Vec<u8> = infos.iter().map(|i| i.parameter_id).collect();
        ids.sort_unstable();
        ids.dedup();
        let Some(curve) = PaceCurve::from_parameter_id(info.parameter_id) else {
            return self.start_bac();
        };
        let rnd = match self.pace_random(curve) {
            Ok(r) => r,
            Err(e) => return self.fail(e),
        };
        let x = match PaceExchange::new(info, self.seed.as_bytes(), rnd) {
            Ok(x) if ids.len() > 1 => x.with_parameter_reference(),
            Ok(x) => x,
            Err(_) => return self.start_bac(),
        };
        let cmd = match x.msg_set_at() {
            Ok(c) => c,
            Err(_) => return self.start_bac(),
        };
        self.phase = Phase::PaceSetAt(Box::new(x));
        self.send_plain(cmd)
    }

    /// BAC: SELECT the applet, GET CHALLENGE, MUTUAL AUTHENTICATE. Runs at
    /// most once (after a PACE failure it is the only fallback).
    fn start_bac(&mut self) -> Step {
        self.channel = None;
        self.chained.clear();
        self.phase = Phase::BacSelect;
        self.send_plain(Command::select_applet(&AID_EMRTD))
    }

    fn select_file(&mut self, fid: u16) -> Step {
        self.phase = Phase::FileSelect(fid);
        self.send_sm(Command::select_ef(fid))
    }

    fn read_next(&mut self, mut f: FileRead) -> Step {
        let cmd = f.next_cmd();
        if f.fid == EF_CARD_ACCESS {
            self.phase = Phase::CardAccessRead(f);
            self.send_plain(cmd)
        } else {
            self.phase = Phase::FileRead(f);
            self.send_sm(cmd)
        }
    }

    fn file_done(&mut self, f: FileRead) -> Step {
        let FileRead { fid, buf, .. } = f;
        self.sizes.push((fid, buf.len()));
        self.progress_files.push(fid);
        match fid {
            EF_COM => match parse_com(&buf) {
                Ok(tags) => {
                    self.tags = tags;
                    self.select_file(EF_SOD)
                }
                Err(e) => self.fail(e),
            },
            EF_SOD => {
                self.sod = buf;
                self.select_file(EF_DG1)
            }
            EF_DG1 => {
                match parse_dg1(&buf) {
                    // The access key fields: names and optional data may
                    // differ from an imperfect OCR, the result uses DG1's.
                    Ok(m)
                        if m.document_number == self.scanned.document_number
                            && m.birth_date == self.scanned.birth_date
                            && m.expiry_date == self.scanned.expiry_date => {}
                    // The chip holds another document than the one scanned.
                    Ok(_) => return self.fail(IcaoError::AccessDenied),
                    Err(e) => return self.fail(e),
                }
                self.dg1 = buf;
                if self.tags.contains(&0x75) {
                    self.select_file(EF_DG2)
                } else {
                    self.finish()
                }
            }
            EF_DG2 => {
                self.dg2 = Some(buf);
                self.finish()
            }
            _ => self.fail(IcaoError::Protocol("unexpected-file")),
        }
    }

    fn finish(&mut self) -> Step {
        let mrz = match parse_dg1(&self.dg1) {
            Ok(m) => m,
            Err(e) => return self.fail(e),
        };
        let portrait = self.dg2.as_ref().and_then(|b| parse_dg2(b).ok());
        let mut dgs: Vec<(u8, &[u8])> = vec![(1, &self.dg1[..])];
        if let Some(b) = &self.dg2 {
            dgs.push((2, &b[..]));
        }
        let status = verify_sod(&self.sod, &dgs, &self.master_list, self.today);
        let read = ChipRead {
            mrz,
            portrait,
            status,
            progress_files: std::mem::take(&mut self.progress_files),
        };
        self.end();
        self.progress = 1.0;
        Step::Done(read)
    }

    fn fail(&mut self, e: IcaoError) -> Step {
        self.end();
        Step::Failed(e)
    }

    /// Drop the channel and every buffer.
    fn end(&mut self) {
        self.phase = Phase::Finished;
        self.channel = None;
        self.last = None;
        self.chained = Zeroizing::new(Vec::new());
        self.sod = Zeroizing::new(Vec::new());
        self.dg1 = Zeroizing::new(Vec::new());
        self.dg2 = None;
    }

    fn send_plain(&mut self, cmd: Command) -> Step {
        self.retries = 0;
        self.send_plain_keep(cmd)
    }

    /// Send without resetting the 6Cxx / 61xx retry count.
    fn send_plain_keep(&mut self, cmd: Command) -> Step {
        let bytes = cmd.to_bytes();
        self.last = Some(cmd);
        Step::Send(bytes)
    }

    fn send_sm(&mut self, cmd: Command) -> Step {
        self.last = None;
        match self.channel.as_mut() {
            Some(ch) => Step::Send(ch.wrap(&cmd).to_bytes()),
            None => self.fail(IcaoError::Protocol("no-secure-channel")),
        }
    }

    fn bac_random(&self) -> Result<([u8; 8], Zeroizing<[u8; 16]>), IcaoError> {
        match &self.rng {
            Rng::Os => {
                let mut rnd = [0u8; 8];
                let mut k = Zeroizing::new([0u8; 16]);
                aws_lc_rs::rand::fill(&mut rnd).map_err(|_| IcaoError::Crypto)?;
                aws_lc_rs::rand::fill(&mut *k).map_err(|_| IcaoError::Crypto)?;
                Ok((rnd, k))
            }
            #[cfg(feature = "scan-test-rng")]
            Rng::Fixed(r) => Ok((r.bac_rnd_ifd, Zeroizing::new(r.bac_k_ifd))),
        }
    }

    fn pace_random(&self, curve: PaceCurve) -> Result<PaceRandom, IcaoError> {
        match &self.rng {
            Rng::Os => PaceRandom::generate(curve),
            #[cfg(feature = "scan-test-rng")]
            Rng::Fixed(r) => Ok(PaceRandom::new(&r.pace_map_sk, &r.pace_eph_sk)),
        }
    }

    /// Bytes read over bytes expected, guessing the size of the files not
    /// opened yet. Never goes back; 1 only once done.
    fn update_progress(&mut self, step: &Step) {
        if !matches!(step, Step::Send(_)) {
            return;
        }
        let (cur_fid, cur_read, cur_total) = match &self.phase {
            Phase::FileRead(f) => (Some(f.fid), f.buf.len(), f.total),
            _ => (None, 0, None),
        };
        let mut read = cur_read;
        let mut total = 0usize;
        for (fid, guess) in GUESS {
            if fid == EF_DG2 && !self.tags.is_empty() && !self.tags.contains(&0x75) {
                continue;
            }
            if let Some(&(_, n)) = self.sizes.iter().find(|(f, _)| *f == fid) {
                read += n;
                total += n;
            } else if cur_fid == Some(fid) {
                total += cur_total.unwrap_or(guess).max(cur_read);
            } else {
                total += guess;
            }
        }
        if total == 0 {
            return;
        }
        let p = (read as f32 / total as f32).min(0.99);
        if p > self.progress {
            self.progress = p;
        }
    }
}
