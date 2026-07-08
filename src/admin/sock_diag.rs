// Security Center - Netlink sock_diag byte accounting
// Copyright (C) 2026 Christos Daggas
// SPDX-License-Identifier: MIT

//! Per-socket byte counters via the kernel's `NETLINK_SOCK_DIAG` interface.
//!
//! Unlike `/proc/net/tcp` (which only exposes queue sizes), sock_diag with the
//! `INET_DIAG_INFO` extension returns `tcp_info`, including cumulative bytes
//! sent and received per socket — all unprivileged, in a single dump. We
//! aggregate those by remote host to produce a real "top talkers" ranking.
//!
//! Everything here is best-effort: any failure returns an error so the caller
//! can fall back to a connection-count view instead of showing nothing.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{anyhow, Result};
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_sock_diag::{
    constants::{AF_INET, AF_INET6, IPPROTO_TCP},
    inet::{nlas::Nla, ExtensionFlags, InetRequest, SocketId, StateFlags},
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

/// Cumulative traffic to/from a single remote host.
#[derive(Debug, Clone)]
pub struct TalkerBytes {
    pub addr: IpAddr,
    /// Bytes received from this host (sum over its sockets).
    pub bytes_in: u64,
    /// Bytes sent to this host (sum over its sockets).
    pub bytes_out: u64,
}

impl TalkerBytes {
    pub fn total(&self) -> u64 {
        self.bytes_in.saturating_add(self.bytes_out)
    }
}

/// Collect cumulative (bytes_in, bytes_out) per socket inode for established
/// TCP sockets. Used to attribute traffic to processes via the inode→PID map.
pub fn collect_socket_bytes() -> Result<HashMap<u32, (u64, u64)>> {
    let mut by_inode: HashMap<u32, (u64, u64)> = HashMap::new();
    let mut any_ok = false;
    for family in [AF_INET, AF_INET6] {
        if let Ok(rows) = query_family_inode(family) {
            any_ok = true;
            for (inode, bin, bout) in rows {
                let e = by_inode.entry(inode).or_insert((0, 0));
                e.0 = e.0.saturating_add(bin);
                e.1 = e.1.saturating_add(bout);
            }
        }
    }
    if any_ok {
        Ok(by_inode)
    } else {
        Err(anyhow!("sock_diag unavailable"))
    }
}

/// Collect per-remote-host byte totals for established TCP sockets,
/// sorted by total bytes descending. Loopback/unspecified peers are dropped.
pub fn collect_top_talkers() -> Result<Vec<TalkerBytes>> {
    let mut totals: HashMap<IpAddr, (u64, u64)> = HashMap::new();

    // Query both address families; ignore a family that fails so a v6-less
    // host still gets v4 results.
    let mut any_ok = false;
    for family in [AF_INET, AF_INET6] {
        match query_family(family) {
            Ok(rows) => {
                any_ok = true;
                for (addr, bin, bout) in rows {
                    if addr.is_loopback() || addr.is_unspecified() {
                        continue;
                    }
                    let entry = totals.entry(addr).or_insert((0, 0));
                    entry.0 = entry.0.saturating_add(bin);
                    entry.1 = entry.1.saturating_add(bout);
                }
            }
            Err(e) => tracing::debug!("sock_diag family {} failed: {}", family, e),
        }
    }

    if !any_ok {
        return Err(anyhow!("sock_diag unavailable"));
    }

    let mut result: Vec<TalkerBytes> = totals
        .into_iter()
        .map(|(addr, (bytes_in, bytes_out))| TalkerBytes { addr, bytes_in, bytes_out })
        .collect();
    result.sort_by(|a, b| b.total().cmp(&a.total()).then(a.addr.cmp(&b.addr)));
    Ok(result)
}

/// Like `query_family`, but keys results by socket inode instead of remote
/// address, for per-process attribution.
fn query_family_inode(family: u8) -> Result<Vec<(u32, u64, u64)>> {
    query_family_with(family, |resp| {
        let inode = resp.header.inode;
        let (mut bin, mut bout) = (0u64, 0u64);
        for nla in resp.nlas.iter() {
            if let Nla::TcpInfo(info) = nla {
                bin = info.bytes_received;
                bout = info.bytes_acked;
            }
        }
        Some((inode, bin, bout))
    })
}

/// Dump established TCP sockets for one address family, returning
/// `(remote_addr, bytes_in, bytes_out)` per socket.
fn query_family(family: u8) -> Result<Vec<(IpAddr, u64, u64)>> {
    query_family_with(family, |resp| {
        let addr = resp.header.socket_id.destination_address;
        let (mut bin, mut bout) = (0u64, 0u64);
        for nla in resp.nlas.iter() {
            if let Nla::TcpInfo(info) = nla {
                bin = info.bytes_received;
                bout = info.bytes_acked;
            }
        }
        Some((addr, bin, bout))
    })
}

/// Shared netlink dump driver: sends an INET_DIAG request for `family` and
/// maps each response through `extract`.
fn query_family_with<T>(
    family: u8,
    extract: impl Fn(&netlink_packet_sock_diag::inet::InetResponse) -> Option<T>,
) -> Result<Vec<T>> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let socket_id = if family == AF_INET {
        SocketId::new_v4()
    } else {
        SocketId::new_v6()
    };

    let mut nl_hdr = NetlinkHeader::default();
    nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut packet = NetlinkMessage::new(
        nl_hdr,
        SockDiagMessage::InetRequest(InetRequest {
            family,
            protocol: IPPROTO_TCP,
            extensions: ExtensionFlags::INFO,
            states: StateFlags::ESTABLISHED,
            socket_id,
        })
        .into(),
    );
    packet.finalize();

    let mut buf = vec![0u8; packet.buffer_len()];
    packet.serialize(&mut buf[..]);
    socket.send(&buf[..], 0)?;

    let mut rows = Vec::new();
    let mut recv_buf = vec![0u8; 16 * 1024];
    // Safety cap: never loop forever if the kernel misbehaves.
    let mut guard = 0usize;

    'recv: while let Ok(size) = socket.recv(&mut &mut recv_buf[..], 0) {
        guard += 1;
        if guard > 10_000 {
            break;
        }
        if size == 0 {
            break;
        }

        let mut offset = 0;
        while offset < size {
            let bytes = &recv_buf[offset..size];
            let rx = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes)
                .map_err(|e| anyhow!("netlink decode error: {}", e))?;

            let len = rx.header.length as usize;

            match rx.payload {
                NetlinkPayload::Done(_) => break 'recv,
                NetlinkPayload::Error(e) => {
                    return Err(anyhow!("netlink error: {:?}", e));
                }
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(resp)) => {
                    if let Some(row) = extract(&resp) {
                        rows.push(row);
                    }
                }
                _ => {}
            }

            if len == 0 {
                break 'recv;
            }
            offset += len;
        }
    }

    Ok(rows)
}
