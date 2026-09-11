// Integration tests for iroh transport and PKI authentication.
//
// Each test spawns a localhost iroh-relay server, creates endpoints pointed
// at it, and validates the full stack: endpoint binding → relay negotiation
// → QUIC stream → irpc dispatch → PKI auth.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::Signer;
use zedra_host::identity::HostIdentity;
use zedra_host::iroh_listener;
use zedra_host::rpc_daemon::DaemonState;
use zedra_host::session_registry::{PairingSlotMode, SessionRegistry};
use zedra_rpc::proto::{self, *};
use zedra_rpc::{decode_endpoint_addr, encode_endpoint_addr};

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Spawn a local iroh-relay server for testing.
async fn spawn_test_relay() -> anyhow::Result<(iroh_relay::server::Server, iroh::RelayUrl)> {
    let config = iroh_relay::server::testing::server_config();
    let server = iroh_relay::server::Server::spawn(config)
        .await
        .map_err(|e| anyhow::anyhow!("failed to spawn test relay: {:?}", e))?;
    let url = server
        .https_url()
        .or_else(|| server.http_url())
        .ok_or_else(|| anyhow::anyhow!("test relay has no URL"))?;
    Ok((server, url))
}

/// Create an iroh endpoint pointed at the test relay.
async fn make_endpoint(relay_url: iroh::RelayUrl) -> anyhow::Result<iroh::Endpoint> {
    let secret_key = iroh::SecretKey::from(rand::random::<[u8; 32]>());
    let endpoint = iroh::Endpoint::builder()
        .relay_mode(iroh::RelayMode::custom([relay_url]))
        .secret_key(secret_key)
        .alpns(vec![proto::ZEDRA_ALPN.to_vec()])
        .insecure_skip_relay_cert_verify(true)
        .bind()
        .await?;
    Ok(endpoint)
}

async fn wait_online(endpoint: &iroh::Endpoint) {
    tokio::time::timeout(Duration::from_secs(15), endpoint.online())
        .await
        .ok();
}

/// Set up a host: endpoint + accept loop + DaemonState with temp workdir.
/// Returns (endpoint, registry, identity, tempdir).
async fn setup_host(
    relay_url: iroh::RelayUrl,
) -> anyhow::Result<(
    iroh::Endpoint,
    Arc<SessionRegistry>,
    Arc<HostIdentity>,
    tempfile::TempDir,
)> {
    let dir = tempfile::tempdir()?;

    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()?;
    std::process::Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(dir.path())
        .output()?;
    std::process::Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir.path())
        .output()?;
    std::fs::write(dir.path().join("hello.txt"), "hello world")?;

    let identity = Arc::new(HostIdentity::load_or_generate_for_workdir(dir.path())?);
    let state = Arc::new(DaemonState::new(
        dir.path().to_path_buf(),
        identity.clone(),
        [7; 32],
        None,
    ));
    let registry = Arc::new(SessionRegistry::new());

    let endpoint = make_endpoint(relay_url).await?;
    wait_online(&endpoint).await;

    let ep = endpoint.clone();
    let reg = registry.clone();
    tokio::spawn(async move {
        let _ = iroh_listener::run_accept_loop(&ep, reg, state).await;
    });

    Ok((endpoint, registry, identity, dir))
}

/// Connect a client to the host and perform PKI authentication.
///
/// Generates an ephemeral client keypair, adds a pairing slot to the
/// registry, and runs Register → Connect → Challenge → AuthProve.
async fn register_client_for_session(
    relay_url: iroh::RelayUrl,
    host_endpoint: &iroh::Endpoint,
    registry: &Arc<SessionRegistry>,
    session_id: &str,
) -> anyhow::Result<(
    irpc::Client<ZedraProto>,
    ed25519_dalek::SigningKey,
    [u8; 32],
)> {
    let (client, signing_key, pubkey, _conn) =
        register_client_for_session_with_connection(relay_url, host_endpoint, registry, session_id)
            .await?;
    Ok((client, signing_key, pubkey))
}

async fn register_client_for_session_with_connection(
    relay_url: iroh::RelayUrl,
    host_endpoint: &iroh::Endpoint,
    registry: &Arc<SessionRegistry>,
    session_id: &str,
) -> anyhow::Result<(
    irpc::Client<ZedraProto>,
    ed25519_dalek::SigningKey,
    [u8; 32],
    iroh::endpoint::Connection,
)> {
    use ed25519_dalek::SigningKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    let client_signing_key = SigningKey::generate(&mut rand::thread_rng());
    let client_pubkey = client_signing_key.verifying_key().to_bytes();

    let handshake_key: [u8; 16] = rand::random();
    registry.add_pairing_slot(session_id, handshake_key).await;

    let client_endpoint = make_endpoint(relay_url).await?;
    wait_online(&client_endpoint).await;

    let conn = client_endpoint
        .connect(host_endpoint.addr(), proto::ZEDRA_ALPN)
        .await?;
    let remote = irpc_iroh::IrohRemoteConnection::new(conn.clone());
    let client = irpc::Client::<ZedraProto>::boxed(remote);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hmac = zedra_rpc::compute_registration_hmac(&handshake_key, &client_pubkey, timestamp);
    let reg_result: RegisterResult = client
        .rpc(RegisterReq {
            client_pubkey,
            timestamp,
            hmac,
            session_id: session_id.to_string(),
        })
        .await?;
    if !matches!(reg_result, RegisterResult::Ok) {
        anyhow::bail!("register failed: {:?}", reg_result);
    }

    Ok((client, client_signing_key, client_pubkey, conn))
}

async fn register_client_with_handshake_key(
    relay_url: iroh::RelayUrl,
    host_endpoint: &iroh::Endpoint,
    session_id: &str,
    handshake_key: [u8; 16],
) -> anyhow::Result<[u8; 32]> {
    let (client_pubkey, result) = register_client_with_handshake_key_result(
        relay_url,
        host_endpoint,
        session_id,
        handshake_key,
    )
    .await?;
    if !matches!(result, RegisterResult::Ok) {
        anyhow::bail!("register failed: {:?}", result);
    }

    Ok(client_pubkey)
}

async fn register_client_with_handshake_key_result(
    relay_url: iroh::RelayUrl,
    host_endpoint: &iroh::Endpoint,
    session_id: &str,
    handshake_key: [u8; 16],
) -> anyhow::Result<([u8; 32], RegisterResult)> {
    use ed25519_dalek::SigningKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    let client_signing_key = SigningKey::generate(&mut rand::thread_rng());
    let client_pubkey = client_signing_key.verifying_key().to_bytes();
    let client_endpoint = make_endpoint(relay_url).await?;
    wait_online(&client_endpoint).await;

    let conn = client_endpoint
        .connect(host_endpoint.addr(), proto::ZEDRA_ALPN)
        .await?;
    let remote = irpc_iroh::IrohRemoteConnection::new(conn);
    let client = irpc::Client::<ZedraProto>::boxed(remote);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hmac = zedra_rpc::compute_registration_hmac(&handshake_key, &client_pubkey, timestamp);

    let result: RegisterResult = client
        .rpc(RegisterReq {
            client_pubkey,
            timestamp,
            hmac,
            session_id: session_id.to_string(),
        })
        .await?;
    Ok((client_pubkey, result))
}

async fn prove_registered_client(
    client: &irpc::Client<ZedraProto>,
    client_signing_key: &ed25519_dalek::SigningKey,
    client_pubkey: [u8; 32],
    session_id: &str,
    host_identity: &Arc<HostIdentity>,
) -> anyhow::Result<AuthProveResult> {
    use ed25519_dalek::{Verifier, VerifyingKey};

    let connect_result: ConnectResult = client
        .rpc(ConnectReq {
            client_pubkey,
            session_id: session_id.to_string(),
            session_token: None,
        })
        .await?;

    let nonce = match connect_result {
        ConnectResult::Challenge {
            nonce,
            host_signature,
        } => {
            let host_pk_bytes = *host_identity.endpoint_id().as_bytes();
            let host_vk = VerifyingKey::from_bytes(&host_pk_bytes)?;
            let host_sig = ed25519_dalek::Signature::from_bytes(&host_signature);
            host_vk.verify(&nonce, &host_sig)?;
            nonce
        }
        other => anyhow::bail!("expected Challenge, got {:?}", other),
    };

    let client_signature = client_signing_key.sign(&nonce).to_bytes();
    Ok(client
        .rpc(AuthProveReq {
            nonce,
            client_signature,
            session_id: session_id.to_string(),
        })
        .await?)
}

async fn connect_client(
    relay_url: iroh::RelayUrl,
    host_endpoint: &iroh::Endpoint,
    registry: &Arc<SessionRegistry>,
    host_identity: &Arc<HostIdentity>,
) -> anyhow::Result<(
    irpc::Client<ZedraProto>,
    String,
    [u8; 32],
    SyncSessionResult,
)> {
    let (client, session_id, pubkey, sync, _conn) =
        connect_client_with_connection(relay_url, host_endpoint, registry, host_identity).await?;
    Ok((client, session_id, pubkey, sync))
}

async fn connect_client_with_connection(
    relay_url: iroh::RelayUrl,
    host_endpoint: &iroh::Endpoint,
    registry: &Arc<SessionRegistry>,
    host_identity: &Arc<HostIdentity>,
) -> anyhow::Result<(
    irpc::Client<ZedraProto>,
    String,
    [u8; 32],
    SyncSessionResult,
    iroh::endpoint::Connection,
)> {
    let session = registry
        .create_named("test", std::path::PathBuf::from("/tmp/test"))
        .await;

    let (client, client_signing_key, client_pubkey, conn) =
        register_client_for_session_with_connection(
            relay_url,
            host_endpoint,
            registry,
            &session.id,
        )
        .await?;

    let prove_result = prove_registered_client(
        &client,
        &client_signing_key,
        client_pubkey,
        &session.id,
        host_identity,
    )
    .await?;

    let sync = match prove_result {
        AuthProveResult::Ok(sync) => sync,
        other => anyhow::bail!("auth prove failed: {:?}", other),
    };

    Ok((client, session.id.clone(), client_pubkey, sync, conn))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Two endpoints connect and exchange raw bytes via the localhost relay.
#[tokio::test(flavor = "multi_thread")]
async fn test_relay_endpoint_connectivity() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();

    let ep_a = make_endpoint(relay_url.clone()).await.unwrap();
    let ep_b = make_endpoint(relay_url).await.unwrap();

    wait_online(&ep_a).await;
    wait_online(&ep_b).await;

    let ep_a_addr = ep_a.addr();
    let ep_a_clone = ep_a.clone();

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let accept_handle = tokio::spawn(async move {
        let incoming = ep_a_clone.accept().await.expect("no incoming");
        let conn = incoming.accept().unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();

        let mut buf = [0u8; 5];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        send.write_all(b"world").await.unwrap();

        let _ = done_rx.await;
    });

    let conn = ep_b.connect(ep_a_addr, proto::ZEDRA_ALPN).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    send.write_all(b"hello").await.unwrap();

    let mut buf = [0u8; 5];
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"world");

    let _ = done_tx.send(());
    accept_handle.await.unwrap();
}

/// irpc correctly serializes and deserializes Ping messages over real QUIC streams.
#[tokio::test(flavor = "multi_thread")]
async fn test_iroh_transport_framing() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();

    let ep_a = make_endpoint(relay_url.clone()).await.unwrap();
    let ep_b = make_endpoint(relay_url).await.unwrap();

    wait_online(&ep_a).await;
    wait_online(&ep_b).await;

    let ep_a_addr = ep_a.addr();
    let ep_a_clone = ep_a.clone();

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    // Server side: accept and handle one irpc Ping
    let server_handle = tokio::spawn(async move {
        let incoming = ep_a_clone.accept().await.expect("no incoming");
        let conn = incoming.accept().unwrap().await.unwrap();

        let msg = irpc_iroh::read_request::<ZedraProto>(&conn).await.unwrap();

        match msg {
            Some(ZedraMessage::Ping(ping)) => {
                let ts = ping.timestamp_ms;
                let _ = ping.tx.send(PongResult { timestamp_ms: ts }).await;
            }
            other => panic!("expected Ping, got {:?}", other.is_some()),
        }

        let _ = done_rx.await;
    });

    // Client side: connect and send a Ping
    let conn = ep_b.connect(ep_a_addr, proto::ZEDRA_ALPN).await.unwrap();
    let remote = irpc_iroh::IrohRemoteConnection::new(conn);
    let client = irpc::Client::<ZedraProto>::boxed(remote);

    let result: PongResult = client
        .rpc(PingReq {
            timestamp_ms: 12345,
        })
        .await
        .unwrap();
    assert_eq!(result.timestamp_ms, 12345);

    let _ = done_tx.send(());
    server_handle.await.unwrap();
}

/// Full RPC call over iroh — host runs accept loop, client issues GetSessionInfo.
#[tokio::test(flavor = "multi_thread")]
async fn test_full_rpc_over_iroh() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, identity, _dir) = setup_host(relay_url.clone()).await.unwrap();

    let (client, session_id, _client_pubkey, sync) =
        connect_client(relay_url, &host_ep, &registry, &identity)
            .await
            .unwrap();
    assert!(!session_id.is_empty());
    assert_eq!(sync.session_id, session_id);
    assert_ne!(sync.session_token, [0u8; 32]);

    let info: SessionInfoResult = client.rpc(SessionInfoReq {}).await.unwrap();
    assert!(!info.hostname.is_empty());
    assert!(!info.workdir.is_empty());
    assert_eq!(info.session_id.as_deref(), Some(session_id.as_str()));
}

/// A new authorized client is still blocked while the current active client is live.
#[tokio::test(flavor = "multi_thread")]
async fn test_live_second_client_auth_returns_host_occupied() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, identity, _dir) = setup_host(relay_url.clone()).await.unwrap();

    let (client_a, session_id, _client_a_pubkey, _sync) =
        connect_client(relay_url.clone(), &host_ep, &registry, &identity)
            .await
            .unwrap();

    let (client_b, signing_key_b, pubkey_b) =
        register_client_for_session(relay_url, &host_ep, &registry, &session_id)
            .await
            .unwrap();
    let result =
        prove_registered_client(&client_b, &signing_key_b, pubkey_b, &session_id, &identity)
            .await
            .unwrap();

    assert!(
        matches!(result, AuthProveResult::SessionOccupied),
        "expected SessionOccupied, got {:?}",
        result
    );

    let info: SessionInfoResult = client_a.rpc(SessionInfoReq {}).await.unwrap();
    assert_eq!(info.session_id.as_deref(), Some(session_id.as_str()));
}

/// A client-side close should release the host slot before the stale timer.
#[tokio::test(flavor = "multi_thread")]
async fn test_second_client_auth_succeeds_after_first_client_close() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, identity, _dir) = setup_host(relay_url.clone()).await.unwrap();

    let (_client_a, session_id, _client_a_pubkey, _sync, conn_a) =
        connect_client_with_connection(relay_url.clone(), &host_ep, &registry, &identity)
            .await
            .unwrap();
    conn_a.close(0u32.into(), b"test client disconnect");

    let session = registry.get(&session_id).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while session.is_occupied().await {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("host did not observe client close");

    let (client_b, signing_key_b, pubkey_b) =
        register_client_for_session(relay_url, &host_ep, &registry, &session_id)
            .await
            .unwrap();
    let result =
        prove_registered_client(&client_b, &signing_key_b, pubkey_b, &session_id, &identity)
            .await
            .unwrap();

    assert!(
        matches!(result, AuthProveResult::Ok(_)),
        "expected client B to attach after client A close, got {:?}",
        result
    );
}

/// SwitchSession is kept in the protocol, but the host cannot change the
/// per-connection dispatch session after authentication.
#[tokio::test(flavor = "multi_thread")]
async fn test_switch_session_returns_explicit_unsupported_result() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, identity, _dir) = setup_host(relay_url.clone()).await.unwrap();

    let (client, _session_id, _client_pubkey, _sync) =
        connect_client(relay_url, &host_ep, &registry, &identity)
            .await
            .unwrap();

    let result: SessionSwitchResult = client
        .rpc(SessionSwitchReq {
            session_name: "test".to_string(),
            last_notif_seq: 0,
        })
        .await
        .unwrap();

    assert!(result.session_id.is_empty());
    assert!(result.workdir.is_none());
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("unsupported")),
        "expected unsupported error, got {:?}",
        result.error
    );
}

/// Host info snapshots stream over a separate server-streaming subscription.
#[tokio::test(flavor = "multi_thread")]
async fn test_host_info_subscription_over_relay() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, identity, _dir) = setup_host(relay_url.clone()).await.unwrap();

    let (client, _session_id, _client_pubkey, _sync) =
        connect_client(relay_url, &host_ep, &registry, &identity)
            .await
            .unwrap();

    let mut snapshots = client
        .server_streaming(SubscribeHostInfoReq {}, 4)
        .await
        .unwrap();

    let first = tokio::time::timeout(Duration::from_secs(8), snapshots.recv())
        .await
        .expect("timed out waiting for first host info snapshot")
        .unwrap()
        .expect("host info stream closed before first snapshot");
    assert!(first.captured_at_ms > 0);
    assert!(first.cpu_count > 0);
    assert!(first.memory_total_bytes > 0);
    assert!(first.memory_used_bytes <= first.memory_total_bytes);

    let second = tokio::time::timeout(Duration::from_secs(7), snapshots.recv())
        .await
        .expect("timed out waiting for second host info snapshot")
        .unwrap()
        .expect("host info stream closed before second snapshot");
    assert!(second.captured_at_ms >= first.captured_at_ms);
}

/// Terminal creation and I/O over iroh relay using bidi streaming.
#[tokio::test(flavor = "multi_thread")]
async fn test_rpc_terminal_over_relay() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, identity, _dir) = setup_host(relay_url.clone()).await.unwrap();

    let (client, session_id, _client_pubkey, _sync) =
        connect_client(relay_url, &host_ep, &registry, &identity)
            .await
            .unwrap();

    // Create terminal
    let result: TermCreateResult = client
        .rpc(TermCreateReq {
            cols: 80,
            rows: 24,
            launch_cmd: None,
        })
        .await
        .unwrap();
    assert!(uuid::Uuid::parse_str(&result.id).is_ok());
    let terminal_id = result.id.clone();

    #[cfg(unix)]
    let child_pid = {
        let session = registry.get(&session_id).await.unwrap();
        let terminals = session.terminals.lock().await;
        terminals
            .get(&terminal_id)
            .and_then(|terminal| terminal.child.process_id())
            .expect("terminal child should have a pid")
    };

    // Attach to terminal via bidi streaming
    let (input_tx, mut output_rx) = client
        .bidi_streaming::<TermAttachReq, TermInput, TermOutput>(
            TermAttachReq {
                id: terminal_id.clone(),
                last_seq: 0,
            },
            256,
            256,
        )
        .await
        .unwrap();

    // Send a command
    input_tx
        .send(TermInput {
            data: b"echo test123\n".to_vec(),
        })
        .await
        .unwrap();

    // Should receive terminal output
    let output = tokio::time::timeout(Duration::from_secs(5), output_rx.recv())
        .await
        .expect("timed out waiting for terminal output");
    match output {
        Ok(Some(out)) => assert!(!out.data.is_empty()),
        other => panic!("expected terminal output, got {:?}", other),
    }

    let close_result: TermCloseResult = client
        .rpc(TermCloseReq {
            id: terminal_id.clone(),
        })
        .await
        .unwrap();
    assert!(close_result.ok);

    let session = registry.get(&session_id).await.unwrap();
    assert!(!session.terminals.lock().await.contains_key(&terminal_id));

    #[cfg(unix)]
    assert!(!process_exists(child_pid));

    let close_again: TermCloseResult = client.rpc(TermCloseReq { id: terminal_id }).await.unwrap();
    assert!(!close_again.ok);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_terminal_reorder_updates_host_list_and_sync_order() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, identity, _dir) = setup_host(relay_url.clone()).await.unwrap();

    let (client, _session_id, _client_pubkey, _sync) =
        connect_client(relay_url, &host_ep, &registry, &identity)
            .await
            .unwrap();

    let mut ids = Vec::new();
    for _ in 0..3 {
        let result: TermCreateResult = client
            .rpc(TermCreateReq {
                cols: 80,
                rows: 24,
                launch_cmd: None,
            })
            .await
            .unwrap();
        assert!(result.error.is_none());
        ids.push(result.id);
    }

    let initial_list: TermListResult = client.rpc(TermListReq {}).await.unwrap();
    assert_eq!(
        initial_list
            .terminals
            .iter()
            .map(|entry| entry.id.clone())
            .collect::<Vec<_>>(),
        ids
    );

    let reordered_ids = vec![ids[2].clone(), ids[0].clone(), ids[1].clone()];
    let reorder: TermReorderResult = client
        .rpc(TermReorderReq {
            ordered_ids: reordered_ids.clone(),
        })
        .await
        .unwrap();
    assert!(reorder.ok, "{:?}", reorder.error);

    let list: TermListResult = client.rpc(TermListReq {}).await.unwrap();
    assert_eq!(
        list.terminals
            .iter()
            .map(|entry| entry.id.clone())
            .collect::<Vec<_>>(),
        reordered_ids
    );
    assert_eq!(
        list.terminals
            .iter()
            .map(|entry| entry.position)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );

    let sync: SyncSessionResult = client.rpc(SyncSessionReq {}).await.unwrap();
    assert_eq!(
        sync.terminals
            .iter()
            .map(|entry| entry.id.clone())
            .collect::<Vec<_>>(),
        reordered_ids
    );
    assert_eq!(
        sync.terminals
            .iter()
            .map(|entry| entry.position)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );

    let duplicate: TermReorderResult = client
        .rpc(TermReorderReq {
            ordered_ids: vec![ids[0].clone(), ids[0].clone(), ids[1].clone()],
        })
        .await
        .unwrap();
    assert!(!duplicate.ok);

    for id in ids {
        let _ = client.rpc(TermCloseReq { id }).await.unwrap();
    }
}

/// Endpoint addr includes relay URL after going online.
#[tokio::test(flavor = "multi_thread")]
async fn test_relay_url_in_endpoint_addr() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let endpoint = make_endpoint(relay_url.clone()).await.unwrap();

    tokio::time::timeout(Duration::from_secs(15), endpoint.online())
        .await
        .expect("endpoint didn't come online in time");

    let addr = endpoint.addr();
    let relay_urls: Vec<_> = addr.relay_urls().collect();

    assert!(
        !relay_urls.is_empty(),
        "endpoint addr should contain at least one relay URL"
    );
    assert_eq!(relay_urls[0].to_string(), relay_url.to_string());
}

/// EndpointAddr round-trip: encode → decode, verify all fields survive.
#[tokio::test(flavor = "multi_thread")]
async fn test_endpoint_addr_roundtrip() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let endpoint = make_endpoint(relay_url.clone()).await.unwrap();

    tokio::time::timeout(Duration::from_secs(15), endpoint.online())
        .await
        .expect("endpoint didn't come online");

    let addr = endpoint.addr();

    let encoded = encode_endpoint_addr(&addr).unwrap();
    assert!(!encoded.is_empty());

    let decoded = decode_endpoint_addr(&encoded).unwrap();
    assert_eq!(decoded.id, addr.id);

    let decoded_relay_urls: Vec<_> = decoded.relay_urls().collect();
    assert!(
        !decoded_relay_urls.is_empty(),
        "decoded endpoint addr should contain the relay URL"
    );
}

/// Verify PKI auth rejects unknown clients.
#[tokio::test(flavor = "multi_thread")]
async fn test_auth_rejects_unauthorized_client() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, _identity, _dir) = setup_host(relay_url.clone()).await.unwrap();

    // Create a session but don't add any pairing slot or client
    registry
        .create_named("test", std::path::PathBuf::from("/tmp"))
        .await;

    let client_endpoint = make_endpoint(relay_url).await.unwrap();
    wait_online(&client_endpoint).await;

    let conn = client_endpoint
        .connect(host_ep.addr(), proto::ZEDRA_ALPN)
        .await
        .unwrap();
    let remote = irpc_iroh::IrohRemoteConnection::new(conn);
    let client = irpc::Client::<ZedraProto>::boxed(remote);

    // Try to connect without registering (unknown client, no session token)
    let unknown_pubkey = [99u8; 32];
    let result: ConnectResult = client
        .rpc(ConnectReq {
            client_pubkey: unknown_pubkey,
            session_id: "nonexistent".to_string(),
            session_token: None,
        })
        .await
        .unwrap();

    assert!(
        matches!(result, ConnectResult::Unauthorized),
        "expected Unauthorized, got {:?}",
        result
    );
}

/// Verify registration HMAC rejection.
#[tokio::test(flavor = "multi_thread")]
async fn test_register_bad_hmac_rejected() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, _identity, _dir) = setup_host(relay_url.clone()).await.unwrap();

    let session = registry
        .create_named("test", std::path::PathBuf::from("/tmp"))
        .await;
    let handshake_key: [u8; 16] = rand::random();
    registry.add_pairing_slot(&session.id, handshake_key).await;

    let client_endpoint = make_endpoint(relay_url).await.unwrap();
    wait_online(&client_endpoint).await;

    let conn = client_endpoint
        .connect(host_ep.addr(), proto::ZEDRA_ALPN)
        .await
        .unwrap();
    let remote = irpc_iroh::IrohRemoteConnection::new(conn);
    let client = irpc::Client::<ZedraProto>::boxed(remote);

    let client_pubkey = [1u8; 32];
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let bad_hmac = [0u8; 32]; // Wrong HMAC

    let result: RegisterResult = client
        .rpc(RegisterReq {
            client_pubkey,
            timestamp,
            hmac: bad_hmac,
            session_id: session.id.clone(),
        })
        .await
        .unwrap();

    assert!(
        matches!(result, RegisterResult::InvalidHandshake),
        "expected InvalidHandshake, got {:?}",
        result
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_static_pairing_slot_registers_multiple_clients() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, _identity, _dir) = setup_host(relay_url.clone()).await.unwrap();
    let session = registry
        .create_named("test", std::path::PathBuf::from("/tmp"))
        .await;
    let handshake_key: [u8; 16] = rand::random();
    registry
        .add_pairing_slot_with_mode(&session.id, handshake_key, PairingSlotMode::Static)
        .await;

    let first_pubkey =
        register_client_with_handshake_key(relay_url.clone(), &host_ep, &session.id, handshake_key)
            .await
            .unwrap();
    let second_pubkey =
        register_client_with_handshake_key(relay_url, &host_ep, &session.id, handshake_key)
            .await
            .unwrap();

    assert_ne!(first_pubkey, second_pubkey);
    assert!(registry.is_globally_authorized(&first_pubkey).await);
    assert!(registry.is_globally_authorized(&second_pubkey).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_superseded_static_qr_returns_slot_not_found() {
    let (_relay, relay_url) = spawn_test_relay().await.unwrap();
    let (host_ep, registry, _identity, _dir) = setup_host(relay_url.clone()).await.unwrap();
    let session = registry
        .create_named("test", std::path::PathBuf::from("/tmp"))
        .await;
    let old_handshake_key: [u8; 16] = rand::random();
    let new_handshake_key: [u8; 16] = rand::random();
    registry
        .add_pairing_slot_with_mode(&session.id, old_handshake_key, PairingSlotMode::Static)
        .await;
    registry
        .add_pairing_slot_with_mode(&session.id, new_handshake_key, PairingSlotMode::Static)
        .await;

    let (_pubkey, result) = register_client_with_handshake_key_result(
        relay_url,
        &host_ep,
        &session.id,
        old_handshake_key,
    )
    .await
    .unwrap();

    assert!(
        matches!(result, RegisterResult::SlotNotFound),
        "expected SlotNotFound, got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// Web client: opencode shares one server across cards, fresh session per card.
// Ignored by default — needs `opencode` on PATH and writes throwaway sessions.
// Run with: cargo test -p zedra-host --test integration -- --ignored opencode
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs opencode on PATH; creates real sessions"]
async fn opencode_web_client_shares_one_server_per_card() {
    use zedra_host::web_client::WebClientManager;

    let workdir = std::env::temp_dir().join(format!("zedra-wc-it-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).unwrap();
    let manager = WebClientManager::new(workdir.clone());

    let a = manager.start("opencode").await.expect("first card");
    let b = manager.start("opencode").await.expect("second card");

    // One shared server: same port, distinct fresh sessions, distinct paths.
    assert_eq!(a.port, b.port, "both cards share one opencode serve");
    assert_ne!(a.path, b.path, "each card is its own fresh session");
    assert!(a.path.contains("/session/") && b.path.contains("/session/"));
    assert_eq!(manager.list().await.len(), 2);

    let port = a.port;
    let alive = |port: u16| async move {
        reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/"))
            .timeout(Duration::from_secs(1))
            .send()
            .await
            .is_ok()
    };
    assert!(alive(port).await, "server up while cards are open");

    // Closing one card leaves the shared server up for the other.
    manager.stop(&a.id).await.unwrap();
    assert_eq!(manager.list().await.len(), 1);
    assert!(alive(port).await, "server stays up while a card remains");

    // Closing the last card reaps the process.
    manager.stop(&b.id).await.unwrap();
    assert!(manager.list().await.is_empty());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !alive(port).await,
        "server reaped after the last card closes"
    );

    std::fs::remove_dir_all(&workdir).ok();
}
// ---------------------------------------------------------------------------
// Real tmux: shared Pi and OMP session lifecycle. Ignored by default — needs
// tmux >= 3.3a on PATH and runs throwaway sessions on a private `-L` socket, so
// the developer's own tmux server is never touched.
// Run with: cargo test -p zedra-host --test integration tmux_shared_agent_session_lifecycle -- --ignored --nocapture
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod tmux_lifecycle {
    use super::*;
    use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
    use std::ffi::{OsStr, OsString};
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;
    use zedra_host::pty::{SharedSpawnIdentity, SpawnOptions, TerminalBacking};
    use zedra_host::rpc_daemon::create_terminal;
    use zedra_host::tmux::{self, TmuxClient};

    /// Best-effort cleanup for the private socket: kill only this test's
    /// server. Never a pattern kill — that would hit unrelated tmux state.
    struct PrivateSocket {
        name: String,
    }

    impl Drop for PrivateSocket {
        fn drop(&mut self) {
            let _ = std::process::Command::new("tmux")
                .args(["-L", &self.name, "kill-server"])
                .output();
        }
    }

    /// A tmux client attached through the production attach command. The child
    /// is `sh -c <command>` and the command `exec`s tmux, so the child process
    /// is the tmux client itself and its exit status is tmux's own.
    struct AttachedClient {
        _master: Box<dyn MasterPty + Send>,
        child: Box<dyn Child + Send + Sync>,
        writer: Box<dyn Write + Send>,
        output: mpsc::Receiver<String>,
        seen: String,
    }

    impl AttachedClient {
        fn spawn(attach_command: &str, cols: u16, rows: u16) -> Self {
            let pair = native_pty_system()
                .openpty(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .expect("open pty for tmux client");
            // tmux clients need a usable TERM or they refuse to attach.
            let mut command = CommandBuilder::new("/bin/sh");
            command.arg("-c");
            command.arg(attach_command);
            command.env("TERM", "xterm-256color");
            let child = pair
                .slave
                .spawn_command(command)
                .expect("spawn tmux client");
            drop(pair.slave);
            let writer = pair.master.take_writer().expect("take client writer");
            let reader = pair.master.try_clone_reader().expect("take client reader");
            let (sender, output) = mpsc::channel();
            thread::spawn(move || {
                let mut reader = reader;
                let mut buffer = [0u8; 8192];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            // The receiver lives as long as the client; a
                            // failed send only means the test already moved on.
                            let _ = sender.send(String::from_utf8_lossy(&buffer[..n]).into_owned());
                        }
                    }
                }
            });
            Self {
                _master: pair.master,
                child,
                writer,
                output,
                seen: String::new(),
            }
        }

        fn pid(&self) -> u32 {
            self.child.process_id().expect("tmux client has a pid")
        }

        fn send(&mut self, line: &str) {
            self.writer
                .write_all(line.as_bytes())
                .and_then(|()| self.writer.flush())
                .expect("write to tmux client");
        }

        /// Drain the reader thread and report whether `pattern` has arrived.
        fn received(&mut self, pattern: &str) -> bool {
            while let Ok(chunk) = self.output.try_recv() {
                self.seen.push_str(&chunk);
            }
            self.seen.contains(pattern)
        }

        fn exited(&mut self) -> bool {
            self.child.try_wait().expect("poll tmux client").is_some()
        }
    }

    impl Drop for AttachedClient {
        fn drop(&mut self) {
            let _ = self.child.kill();
        }
    }

    fn tmux_output(socket: &str, args: &[&str]) -> std::process::Output {
        std::process::Command::new("tmux")
            .args(["-L", socket])
            .args(args)
            .output()
            .expect("spawn tmux")
    }

    fn tmux_text(socket: &str, args: &[&str]) -> String {
        let output = tmux_output(socket, args);
        assert!(
            output.status.success(),
            "tmux {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Poll `condition` for up to five seconds; the final check is authoritative.
    fn wait_for(mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if condition() {
                return true;
            }
            if Instant::now() >= deadline {
                return condition();
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    /// (pane pid, pane dead) of the session's single pane.
    fn pane_state(socket: &str, name: &str) -> Option<(u32, bool)> {
        let line = tmux_text(
            socket,
            &["list-panes", "-t", name, "-F", "#{pane_pid}|#{pane_dead}"],
        );
        let (pid, dead) = line.lines().next()?.split_once('|')?;
        Some((pid.parse().ok()?, dead == "1"))
    }

    fn client_count(socket: &str, name: &str) -> usize {
        tmux_text(
            socket,
            &["list-clients", "-t", name, "-F", "#{client_name}"],
        )
        .lines()
        .count()
    }

    /// Live pane size as `WxH`, from the session's display message.
    fn pane_size(socket: &str, name: &str) -> String {
        let format = "#{pane_width}x#{pane_height}";
        tmux_text(socket, &["display-message", "-p", "-t", name, "-F", format])
            .trim()
            .to_string()
    }

    /// The client name owning `pid`, from the client list itself. Names are
    /// release-dependent; the pid column is not.
    fn client_name_by_pid(socket: &str, name: &str, pid: u32) -> Option<String> {
        let format = "#{client_pid}|#{client_name}";
        tmux_text(socket, &["list-clients", "-t", name, "-F", format])
            .lines()
            .find_map(|line| {
                let (client_pid, client_name) = line.split_once('|')?;
                (client_pid == pid.to_string()).then(|| client_name.to_string())
            })
    }

    #[test]
    #[ignore = "needs tmux >= 3.3a on PATH; creates throwaway sessions on a private socket"]
    fn tmux_shared_agent_session_lifecycle() {
        let Ok(probe) = std::process::Command::new("tmux").arg("-V").output() else {
            eprintln!("skipping tmux_shared_agent_session_lifecycle: no tmux binary on PATH");
            return;
        };
        let version = match tmux::supported_version(&String::from_utf8_lossy(&probe.stdout)) {
            Ok(version) => version,
            Err(reason) => {
                eprintln!("skipping tmux_shared_agent_session_lifecycle: {reason}");
                return;
            }
        };
        eprintln!("tmux_shared_agent_session_lifecycle against tmux {version}");

        let socket = PrivateSocket {
            name: format!("zedra-it-{}", std::process::id()),
        };
        let client = TmuxClient::with_socket("tmux", Some(&socket.name)).expect("tmux client");
        let workdir = tempfile::tempdir().expect("temp workdir");
        std::fs::create_dir(workdir.path().join("elsewhere")).expect("create move target");
        let elsewhere =
            std::fs::canonicalize(workdir.path().join("elsewhere")).expect("canonical target");
        let session_id = format!("lifecycle-{}", std::process::id());
        let pi_name = tmux::owned_session_name("pi", &session_id).expect("Pi owned name");
        let omp_name = tmux::owned_session_name("omp", &session_id).expect("OMP owned name");
        assert_ne!(pi_name, omp_name);
        assert_eq!(
            tmux::session_ownership(&pi_name),
            tmux::SessionOwnership::Owned {
                slug: "pi".to_string(),
                session_id: session_id.clone(),
            }
        );
        assert_eq!(
            tmux::session_ownership(&omp_name),
            tmux::SessionOwnership::Owned {
                slug: "omp".to_string(),
                session_id: session_id.clone(),
            }
        );

        // Concurrent create-or-attach races start exactly one Pi process.
        let pi_attach_commands: Vec<String> = thread::scope(|scope| {
            let session_id = &session_id;
            let workdir = workdir.path();
            let racers: Vec<_> = (0..8)
                .map(|_| {
                    let client = client.clone();
                    scope.spawn(move || {
                        client
                            .prepare_session("pi", session_id, workdir, "sh")
                            .expect("concurrent prepare must succeed")
                    })
                })
                .collect();
            racers
                .into_iter()
                .map(|racer| racer.join().expect("prepare thread"))
                .collect()
        });
        assert!(
            pi_attach_commands
                .iter()
                .all(|command| command == &pi_attach_commands[0]),
            "racers disagree on the attach command: {pi_attach_commands:?}"
        );
        let omp_attach_command = client
            .prepare_session("omp", &session_id, workdir.path(), "sh")
            .expect("prepare OMP session");

        let (pi_pane_pid, pi_dead) =
            pane_state(&socket.name, &pi_name).expect("Pi pane after the race");
        let (omp_pane_pid, omp_dead) =
            pane_state(&socket.name, &omp_name).expect("OMP pane after prepare");
        assert!(!pi_dead && process_exists(pi_pane_pid));
        assert!(!omp_dead && process_exists(omp_pane_pid));

        // A foreign session stays invisible, and each owned listing is isolated
        // by slug even though Pi and OMP use the same provider session id.
        tmux_text(
            &socket.name,
            &[
                "new-session",
                "-d",
                "-s",
                "foreign-lifecycle",
                "-c",
                workdir.path().to_str().expect("UTF-8 workdir"),
                "sh",
            ],
        );
        let pi_panes = client.list_sessions("pi").expect("list Pi sessions");
        let omp_panes = client.list_sessions("omp").expect("list OMP sessions");
        assert_eq!(pi_panes.len(), 1);
        assert_eq!(omp_panes.len(), 1);
        assert_eq!(pi_panes[0].slug, "pi");
        assert_eq!(omp_panes[0].slug, "omp");
        assert_eq!(pi_panes[0].session_id, session_id);
        assert_eq!(omp_panes[0].session_id, session_id);
        assert!(!pi_panes[0].process.dead);
        assert!(!omp_panes[0].process.dead);
        assert!(!pi_panes[0].process.current_command.is_empty());
        assert!(!omp_panes[0].process.current_command.is_empty());
        assert_eq!(pi_panes[0].metadata.start_command, "sh");
        assert_eq!(omp_panes[0].metadata.start_command, "sh");
        let mut listed_pi = || client.list_sessions("pi").unwrap_or_default();
        let mut listed_omp = || client.list_sessions("omp").unwrap_or_default();

        // Two independent clients attach to each provider target.
        let mut pi_desktop = AttachedClient::spawn(&pi_attach_commands[0], 100, 30);
        let mut pi_phone = AttachedClient::spawn(&pi_attach_commands[0], 40, 12);
        let mut omp_desktop = AttachedClient::spawn(&omp_attach_command, 90, 26);
        let mut omp_phone = AttachedClient::spawn(&omp_attach_command, 35, 10);
        assert!(wait_for(|| client_count(&socket.name, &pi_name) == 2));
        assert!(wait_for(|| client_count(&socket.name, &omp_name) == 2));
        for name in [&pi_name, &omp_name] {
            assert_eq!(
                tmux_text(&socket.name, &["show-options", "-v", "-t", name, "mouse"]).trim(),
                "on"
            );
        }
        assert!(
            wait_for(|| pane_size(&socket.name, &pi_name) == "100x29"),
            "Pi pane sizes to the largest client"
        );

        pi_desktop.send("echo pi-desktop-only\n");
        pi_phone.send("echo pi-phone-only\n");
        assert!(wait_for(|| {
            pi_desktop.received("pi-desktop-only")
                && pi_desktop.received("pi-phone-only")
                && pi_phone.received("pi-desktop-only")
                && pi_phone.received("pi-phone-only")
        }));
        assert!(!omp_desktop.received("pi-desktop-only"));
        assert!(!omp_phone.received("pi-phone-only"));

        omp_desktop.send("echo omp-desktop-only\n");
        omp_phone.send("echo omp-phone-only\n");
        assert!(wait_for(|| {
            omp_desktop.received("omp-desktop-only")
                && omp_desktop.received("omp-phone-only")
                && omp_phone.received("omp-desktop-only")
                && omp_phone.received("omp-phone-only")
        }));
        assert!(!pi_desktop.received("omp-desktop-only"));
        assert!(!pi_phone.received("omp-phone-only"));

        // Metadata follows each inner process independently.
        pi_desktop.send("printf '\\033]0;pi-title\\007'\n");
        omp_desktop.send("printf '\\033]0;omp-title\\007'\n");
        assert!(wait_for(|| listed_pi()
            .first()
            .is_some_and(|pane| pane.metadata.title == "pi-title")));
        assert!(wait_for(|| listed_omp()
            .first()
            .is_some_and(|pane| pane.metadata.title == "omp-title")));
        pi_phone.send("cd elsewhere\n");
        let target = elsewhere.to_str().expect("UTF-8 cwd").to_string();
        assert!(wait_for(|| listed_pi()
            .first()
            .is_some_and(|pane| pane.metadata.current_path == target)));
        assert_ne!(listed_omp()[0].metadata.current_path, target);

        // Detaching one client from either target leaves both inner processes
        // and each provider's other client intact.
        for (name, attached) in [(&pi_name, &pi_phone), (&omp_name, &omp_phone)] {
            let client_name = client_name_by_pid(&socket.name, name, attached.pid())
                .expect("attached client is listed");
            let detach = tmux_output(&socket.name, &["detach-client", "-t", &client_name]);
            assert!(
                detach.status.success(),
                "detach failed: {}",
                String::from_utf8_lossy(&detach.stderr)
            );
        }
        assert!(wait_for(|| pi_phone.exited() && omp_phone.exited()));
        assert!(wait_for(|| client_count(&socket.name, &pi_name) == 1));
        assert!(wait_for(|| client_count(&socket.name, &omp_name) == 1));
        assert!(process_exists(pi_pane_pid));
        assert!(process_exists(omp_pane_pid));

        pi_desktop.send("echo pi-after-detach\n");
        omp_desktop.send("echo omp-after-detach\n");
        assert!(wait_for(|| pi_desktop.received("pi-after-detach")));
        assert!(wait_for(|| omp_desktop.received("omp-after-detach")));

        let mut pi_second = AttachedClient::spawn(&pi_attach_commands[0], 90, 26);
        let mut omp_second = AttachedClient::spawn(&omp_attach_command, 80, 24);
        assert!(wait_for(|| client_count(&socket.name, &pi_name) == 2));
        assert!(wait_for(|| client_count(&socket.name, &omp_name) == 2));

        // Terminating OMP ends only OMP; Pi remains live and attachable.
        client
            .terminate_session("omp", &session_id)
            .expect("terminate OMP");
        assert!(wait_for(|| !process_exists(omp_pane_pid)));
        assert!(wait_for(|| omp_desktop.exited() && omp_second.exited()));
        assert!(process_exists(pi_pane_pid));
        assert_eq!(client.list_sessions("pi").expect("list Pi").len(), 1);
        assert!(client
            .list_sessions("omp")
            .expect("list terminated OMP")
            .is_empty());
        pi_desktop.send("echo pi-after-omp-terminate\n");
        assert!(wait_for(|| pi_second.received("pi-after-omp-terminate")));

        client
            .terminate_session("pi", &session_id)
            .expect("terminate Pi");
        assert!(wait_for(|| !process_exists(pi_pane_pid)));
        assert!(wait_for(|| pi_desktop.exited() && pi_second.exited()));
        assert!(client
            .list_sessions("pi")
            .expect("list terminated Pi")
            .is_empty());
        assert!(client.list_sessions("omp").expect("list OMP").is_empty());
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn write_agent_fixture(bin_dir: &Path, slug: &str) {
        let path = bin_dir.join(slug);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf 'fixture:{slug}:ready\\r\\n'\nwhile IFS= read -r line; do\n  printf 'fixture:{slug}:%s\\r\\n' \"$line\"\ndone\n"
            ),
        )
        .expect("write blocking agent fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make agent fixture executable");
    }

    fn new_fixture_session(socket: &str, name: &str, cwd: &Path, command: &str) {
        tmux_text(
            socket,
            &[
                "new-session",
                "-d",
                "-s",
                name,
                "-c",
                cwd.to_str().expect("UTF-8 fixture workdir"),
                command,
            ],
        );
    }

    fn exact_client_count(socket: &str, name: &str) -> usize {
        let target = format!("={name}");
        tmux_text(
            socket,
            &["list-clients", "-t", &target, "-F", "#{client_name}"],
        )
        .lines()
        .count()
    }

    fn exact_session_exists(socket: &str, name: &str) -> bool {
        let target = format!("={name}");
        tmux_output(socket, &["has-session", "-t", &target])
            .status
            .success()
    }

    macro_rules! assert_terminal_output {
        ($receiver:ident, $needle:expr) => {{
            let needle = $needle;
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut seen = String::new();
            loop {
                let now = Instant::now();
                assert!(
                    now < deadline,
                    "terminal output did not contain {needle:?}: {seen:?}"
                );
                let output = tokio::time::timeout(deadline - now, $receiver.recv())
                    .await
                    .expect("timed out waiting for terminal output");
                match output {
                    Ok(Some(output)) => {
                        seen.push_str(&String::from_utf8_lossy(&output.data));
                        if seen.contains(needle) {
                            break;
                        }
                    }
                    Ok(None) => {
                        panic!("terminal output closed before {needle:?} arrived: {seen:?}")
                    }
                    Err(error) => {
                        panic!("terminal output failed before {needle:?} arrived: {error}")
                    }
                }
            }
        }};
    }

    async fn attach_custom_session(client: &irpc::Client<ZedraProto>, name: &str) -> String {
        let result: TmuxSessionAttachResult = client
            .rpc(TmuxSessionAttachReq {
                name: name.to_string(),
                cols: 80,
                rows: 24,
                device_kind: TmuxClientDeviceKind::Desktop,
            })
            .await
            .expect("attach custom tmux RPC");
        assert!(
            result.error.is_none(),
            "attach {name:?} failed: {:?}",
            result.error
        );
        assert!(
            uuid::Uuid::parse_str(&result.terminal_id).is_ok(),
            "host returned a non-UUID terminal id: {:?}",
            result.terminal_id
        );
        result.terminal_id
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs tmux >= 3.3a on PATH; creates agent fixtures and throwaway sessions on a private socket"]
    async fn tmux_custom_agent_session_lifecycle() {
        let Ok(probe) = std::process::Command::new("tmux").arg("-V").output() else {
            eprintln!("skipping tmux_custom_agent_session_lifecycle: no tmux binary on PATH");
            return;
        };
        let version = match tmux::supported_version(&String::from_utf8_lossy(&probe.stdout)) {
            Ok(version) => version,
            Err(reason) => {
                eprintln!("skipping tmux_custom_agent_session_lifecycle: {reason}");
                return;
            }
        };
        eprintln!("tmux_custom_agent_session_lifecycle against tmux {version}");

        let environment = tempfile::tempdir().expect("temp fixture environment");
        let fixture_bin = environment.path().join("bin");
        let test_home = environment.path().join("home");
        std::fs::create_dir_all(&fixture_bin).expect("create fixture bin");
        std::fs::create_dir_all(&test_home).expect("create fixture home");
        for slug in ["pi", "omp", "claude"] {
            write_agent_fixture(&fixture_bin, slug);
        }

        let original_path = std::env::var_os("PATH").unwrap_or_default();
        let fixture_path = std::env::join_paths(
            std::iter::once(fixture_bin.clone()).chain(std::env::split_paths(&original_path)),
        )
        .expect("compose fixture PATH");
        let _home_guard = EnvVarGuard::set("HOME", &test_home);
        let _path_guard = EnvVarGuard::set("PATH", &fixture_path);
        let socket = PrivateSocket {
            name: format!(
                "zedra-custom-it-{}-{:x}",
                std::process::id(),
                rand::random::<u64>()
            ),
        };
        let tmux_client =
            TmuxClient::with_socket("tmux", Some(&socket.name)).expect("private tmux client");

        let cars_name = "cars_us";
        let claude_name = "claude_custom";
        let multi_name = "pi_omp_multi";
        let shell_name = "shell_only";
        let metachar_name = "meta; touch TMUX_COMMAND_INJECTION";
        let owned_session_id = format!("custom-control-{}", std::process::id());
        let owned_name =
            tmux::owned_session_name("pi", &owned_session_id).expect("owned control name");

        new_fixture_session(&socket.name, cars_name, environment.path(), "pi");
        new_fixture_session(&socket.name, claude_name, environment.path(), "claude");
        new_fixture_session(&socket.name, multi_name, environment.path(), "pi");
        let multi_target = format!("={multi_name}:");
        for command in ["omp", "pi"] {
            tmux_text(
                &socket.name,
                &[
                    "split-window",
                    "-d",
                    "-t",
                    &multi_target,
                    "-c",
                    environment.path().to_str().expect("UTF-8 fixture workdir"),
                    command,
                ],
            );
        }
        new_fixture_session(&socket.name, shell_name, environment.path(), "sh");
        new_fixture_session(&socket.name, &owned_name, environment.path(), "pi");
        new_fixture_session(&socket.name, metachar_name, environment.path(), "claude");

        let socket_path = tmux_text(
            &socket.name,
            &[
                "display-message",
                "-p",
                "-t",
                cars_name,
                "-F",
                "#{socket_path}",
            ],
        );
        let socket_path = std::path::PathBuf::from(socket_path.trim());
        assert!(
            socket_path.is_absolute(),
            "tmux returned a relative socket path"
        );
        let config_dir = test_home.join(".config").join("zedra");
        std::fs::create_dir_all(&config_dir).expect("create private global config directory");
        let socket_yaml =
            serde_json::to_string(socket_path.to_str().expect("UTF-8 private socket path"))
                .expect("quote private socket path");
        std::fs::write(
            config_dir.join(zedra_host::global_config::FILE_NAME),
            format!("tmux:\n  socket: {socket_yaml}\n"),
        )
        .expect("write private tmux config");
        zedra_host::global_config::init(environment.path());
        if zedra_host::global_config::get().tmux.socket.as_deref() != Some(socket_path.as_path()) {
            eprintln!(
                "skipping tmux_custom_agent_session_lifecycle: global config was initialized by another ignored test"
            );
            return;
        }

        let (_relay, relay_url) = spawn_test_relay().await.expect("start private relay");
        let (host_ep, registry, identity, host_workdir) =
            setup_host(relay_url.clone()).await.expect("start host");
        let (rpc, session_id, _client_pubkey, _sync) =
            connect_client(relay_url, &host_ep, &registry, &identity)
                .await
                .expect("connect authenticated client");
        let server_session = registry.get(&session_id).await.expect("server session");
        let injection_sentinel = host_workdir.path().join("TMUX_COMMAND_INJECTION");

        let listed: TmuxSessionListResult = rpc
            .rpc(TmuxSessionListReq {})
            .await
            .expect("list custom tmux sessions");
        assert!(listed.available, "tmux unavailable: {:?}", listed.error);
        assert_eq!(listed.version, version.to_string());
        assert!(listed.error.is_none());
        let supported_names = [cars_name, claude_name, metachar_name];
        let enumerated_names = tmux_text(&socket.name, &["list-sessions", "-F", "#{session_name}"]);
        let expected_custom_order: Vec<&str> = enumerated_names
            .lines()
            .filter(|name| supported_names.contains(name))
            .collect();
        assert_eq!(
            listed
                .sessions
                .iter()
                .map(|session| session.name.as_str())
                .collect::<Vec<_>>(),
            expected_custom_order,
            "custom discovery must preserve tmux enumeration order"
        );
        assert_eq!(listed.sessions.len(), supported_names.len());
        for (name, expected_slug) in [
            (cars_name, "pi"),
            (claude_name, "claude"),
            (metachar_name, "claude"),
        ] {
            let session = listed
                .sessions
                .iter()
                .find(|session| session.name == name)
                .unwrap_or_else(|| panic!("custom discovery omitted {name:?}"));
            assert_eq!(
                session.agent_slug, expected_slug,
                "wrong detected actor for {name:?}"
            );
        }
        assert!(
            !listed.sessions.iter().any(|session| {
                session.name == shell_name
                    || session.name == owned_name
                    || session.name == multi_name
            }),
            "shell-only, owned, and multi-agent sessions must stay outside custom discovery"
        );

        let cars_one_id = attach_custom_session(&rpc, cars_name).await;
        let cars_two_id = attach_custom_session(&rpc, cars_name).await;
        assert_ne!(cars_one_id, cars_two_id);
        let (cars_one_input, mut cars_one_output) = rpc
            .bidi_streaming::<TermAttachReq, TermInput, TermOutput>(
                TermAttachReq {
                    id: cars_one_id.clone(),
                    last_seq: 0,
                },
                256,
                256,
            )
            .await
            .expect("attach first cars terminal stream");
        let (cars_two_input, mut cars_two_output) = rpc
            .bidi_streaming::<TermAttachReq, TermInput, TermOutput>(
                TermAttachReq {
                    id: cars_two_id.clone(),
                    last_seq: 0,
                },
                256,
                256,
            )
            .await
            .expect("attach second cars terminal stream");
        assert!(wait_for(|| exact_client_count(&socket.name, cars_name) == 2));
        let (cars_pane_pid, cars_dead) =
            pane_state(&socket.name, cars_name).expect("cars pane state");
        assert!(!cars_dead && process_exists(cars_pane_pid));

        cars_one_input
            .send(TermInput {
                data: b"cars-from-one\n".to_vec(),
            })
            .await
            .expect("write first cars terminal");
        assert_terminal_output!(cars_one_output, "fixture:pi:cars-from-one");
        assert_terminal_output!(cars_two_output, "fixture:pi:cars-from-one");
        cars_two_input
            .send(TermInput {
                data: b"cars-from-two\n".to_vec(),
            })
            .await
            .expect("write second cars terminal");
        assert_terminal_output!(cars_one_output, "fixture:pi:cars-from-two");
        assert_terminal_output!(cars_two_output, "fixture:pi:cars-from-two");

        let closed: TermCloseResult = rpc
            .rpc(TermCloseReq {
                id: cars_one_id.clone(),
            })
            .await
            .expect("close first cars terminal card");
        assert!(closed.ok);
        assert!(wait_for(|| exact_client_count(&socket.name, cars_name) == 1));
        assert!(exact_session_exists(&socket.name, cars_name));
        assert!(process_exists(cars_pane_pid));
        {
            let terminals = server_session.terminals.lock().await;
            assert!(!terminals.contains_key(&cars_one_id));
            assert!(terminals.contains_key(&cars_two_id));
        }
        cars_two_input
            .send(TermInput {
                data: b"cars-after-close\n".to_vec(),
            })
            .await
            .expect("write surviving cars terminal");
        assert_terminal_output!(cars_two_output, "fixture:pi:cars-after-close");

        let claude_id = attach_custom_session(&rpc, claude_name).await;
        let (claude_input, mut claude_output) = rpc
            .bidi_streaming::<TermAttachReq, TermInput, TermOutput>(
                TermAttachReq {
                    id: claude_id.clone(),
                    last_seq: 0,
                },
                256,
                256,
            )
            .await
            .expect("attach Claude terminal stream");
        let (claude_pane_pid, claude_dead) =
            pane_state(&socket.name, claude_name).expect("Claude pane state");
        assert!(!claude_dead && process_exists(claude_pane_pid));

        let owned_attach_command = tmux_client.attach_command(&owned_name);
        let owned_id = create_terminal(
            &server_session,
            80,
            24,
            SpawnOptions {
                workdir: Some(host_workdir.path().to_path_buf()),
                launch_cmd: Some(owned_attach_command),
                identity_launch_cmd: Some("pi".to_string()),
                backing: Some(TerminalBacking::SharedAgent(SharedSpawnIdentity {
                    slug: "pi".to_string(),
                    session_id: owned_session_id.clone(),
                })),
                ..SpawnOptions::default()
            },
        )
        .await
        .expect("create owned control terminal");
        let (owned_input, mut owned_output) = rpc
            .bidi_streaming::<TermAttachReq, TermInput, TermOutput>(
                TermAttachReq {
                    id: owned_id.clone(),
                    last_seq: 0,
                },
                256,
                256,
            )
            .await
            .expect("attach owned control terminal stream");
        let (owned_pane_pid, owned_dead) =
            pane_state(&socket.name, &owned_name).expect("owned pane state");
        assert!(!owned_dead && process_exists(owned_pane_pid));
        assert!(wait_for(
            || exact_client_count(&socket.name, claude_name) == 1
        ));
        assert!(wait_for(
            || exact_client_count(&socket.name, &owned_name) == 1
        ));

        let terminated: TmuxSessionTerminateResult = rpc
            .rpc(TmuxSessionTerminateReq {
                name: cars_name.to_string(),
            })
            .await
            .expect("terminate cars tmux session");
        assert!(terminated.error.is_none(), "{:?}", terminated.error);
        assert_eq!(terminated.terminal_ids, [cars_two_id.clone()]);
        assert!(wait_for(|| !exact_session_exists(&socket.name, cars_name)));
        assert!(wait_for(|| !process_exists(cars_pane_pid)));
        assert!(exact_session_exists(&socket.name, claude_name));
        assert!(exact_session_exists(&socket.name, multi_name));
        assert!(exact_session_exists(&socket.name, metachar_name));
        assert!(exact_session_exists(&socket.name, &owned_name));
        assert!(process_exists(claude_pane_pid));
        assert!(process_exists(owned_pane_pid));
        {
            let terminals = server_session.terminals.lock().await;
            assert!(!terminals.contains_key(&cars_two_id));
            assert!(terminals.contains_key(&claude_id));
            assert!(terminals.contains_key(&owned_id));
        }

        claude_input
            .send(TermInput {
                data: b"claude-after-cars-terminate\n".to_vec(),
            })
            .await
            .expect("write preserved Claude terminal");
        assert_terminal_output!(claude_output, "fixture:claude:claude-after-cars-terminate");
        owned_input
            .send(TermInput {
                data: b"owned-after-cars-terminate\n".to_vec(),
            })
            .await
            .expect("write preserved owned terminal");
        assert_terminal_output!(owned_output, "fixture:pi:owned-after-cars-terminate");

        let listed_after_terminate: TmuxSessionListResult = rpc
            .rpc(TmuxSessionListReq {})
            .await
            .expect("list after custom termination");
        assert!(listed_after_terminate.available);
        assert!(listed_after_terminate.error.is_none());
        let expected_after_terminate: Vec<&str> = expected_custom_order
            .iter()
            .copied()
            .filter(|name| *name != cars_name)
            .collect();
        assert_eq!(
            listed_after_terminate
                .sessions
                .iter()
                .map(|session| session.name.as_str())
                .collect::<Vec<_>>(),
            expected_after_terminate
        );

        let metachar_id = attach_custom_session(&rpc, metachar_name).await;
        let (metachar_input, mut metachar_output) = rpc
            .bidi_streaming::<TermAttachReq, TermInput, TermOutput>(
                TermAttachReq {
                    id: metachar_id.clone(),
                    last_seq: 0,
                },
                256,
                256,
            )
            .await
            .expect("attach metacharacter terminal stream");
        assert!(wait_for(|| {
            exact_client_count(&socket.name, metachar_name) == 1
        }));
        metachar_input
            .send(TermInput {
                data: b"metachar-exact-target\n".to_vec(),
            })
            .await
            .expect("write metacharacter terminal");
        assert_terminal_output!(metachar_output, "fixture:claude:metachar-exact-target");
        assert!(
            !injection_sentinel.exists(),
            "metacharacters in the session name executed during attach"
        );

        let metachar_terminated: TmuxSessionTerminateResult = rpc
            .rpc(TmuxSessionTerminateReq {
                name: metachar_name.to_string(),
            })
            .await
            .expect("terminate exact metacharacter session");
        assert!(
            metachar_terminated.error.is_none(),
            "{:?}",
            metachar_terminated.error
        );
        assert_eq!(metachar_terminated.terminal_ids, [metachar_id]);
        assert!(wait_for(|| {
            !exact_session_exists(&socket.name, metachar_name)
        }));
        assert!(
            !injection_sentinel.exists(),
            "metacharacters in the session name executed during termination"
        );
        assert!(exact_session_exists(&socket.name, claude_name));
        assert!(exact_session_exists(&socket.name, multi_name));
        assert!(exact_session_exists(&socket.name, &owned_name));

        for id in [claude_id, owned_id] {
            let closed: TermCloseResult = rpc
                .rpc(TermCloseReq { id })
                .await
                .expect("close preserved terminal");
            assert!(closed.ok);
        }
    }
}
