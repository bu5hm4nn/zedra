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
// Real tmux: shared Pi session lifecycle. Ignored by default — needs tmux
// >= 3.3a on PATH and runs throwaway sessions on a private `-L` socket, so
// the developer's own tmux server is never touched.
// Run with: cargo test -p zedra-host --test integration tmux_shared_session_lifecycle -- --ignored --nocapture
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod tmux_lifecycle {
    use super::*;
    use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;
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
    fn tmux_shared_session_lifecycle() {
        let Ok(probe) = std::process::Command::new("tmux").arg("-V").output() else {
            eprintln!("skipping tmux_shared_session_lifecycle: no tmux binary on PATH");
            return;
        };
        let version = match tmux::supported_version(&String::from_utf8_lossy(&probe.stdout)) {
            Ok(version) => version,
            Err(reason) => {
                eprintln!("skipping tmux_shared_session_lifecycle: {reason}");
                return;
            }
        };
        eprintln!("tmux_shared_session_lifecycle against tmux {version}");

        let socket = PrivateSocket {
            name: format!("zedra-it-{}", std::process::id()),
        };
        let client = TmuxClient::with_socket("tmux", Some(&socket.name)).expect("tmux client");
        let workdir = tempfile::tempdir().expect("temp workdir");
        std::fs::create_dir(workdir.path().join("elsewhere")).expect("create move target");
        let elsewhere =
            std::fs::canonicalize(workdir.path().join("elsewhere")).expect("canonical target");
        let session_id = format!("lifecycle-{}", std::process::id());
        let name = tmux::owned_session_name(&session_id).expect("owned name");

        // Concurrent create-or-attach races start exactly one inner process.
        let attach_commands: Vec<String> = thread::scope(|scope| {
            let session_id = &session_id;
            let workdir = workdir.path();
            let racers: Vec<_> = (0..8)
                .map(|_| {
                    let client = client.clone();
                    scope.spawn(move || {
                        client
                            .prepare_session(session_id, workdir, "sh")
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
            attach_commands
                .iter()
                .all(|command| command == &attach_commands[0]),
            "racers disagree on the attach command: {attach_commands:?}"
        );
        let (pane_pid, dead) = pane_state(&socket.name, &name).expect("one pane after the race");
        assert!(
            !dead && process_exists(pane_pid),
            "inner process must be alive"
        );

        // The production listing sees exactly the prepared session.
        let panes = client.list_sessions().expect("list sessions");
        let listed = || client.list_sessions().unwrap_or_default();
        assert_eq!(panes.len(), 1, "only the owned session is listed");
        assert_eq!(panes[0].session_id, session_id);
        assert!(!panes[0].process.dead);
        assert!(!panes[0].process.current_command.is_empty());
        assert_eq!(panes[0].metadata.start_command, "sh");

        // Two independent pty clients attach through the production command.
        let mut desktop = AttachedClient::spawn(&attach_commands[0], 100, 30);
        let mut phone = AttachedClient::spawn(&attach_commands[0], 40, 12);
        assert!(
            wait_for(|| client_count(&socket.name, &name) == 2),
            "both clients attached"
        );
        assert_eq!(
            tmux_text(&socket.name, &["show-options", "-v", "-t", &name, "mouse"]).trim(),
            "on",
            "prepare_session must leave mouse on"
        );
        assert!(
            wait_for(|| pane_size(&socket.name, &name) == "100x29"),
            "pane sizes to the largest client"
        );

        // Input through both clients reaches the single inner process.
        desktop.send("echo it-desktop\n");
        phone.send("echo it-phone\n");
        assert!(
            wait_for(|| {
                desktop.received("it-desktop")
                    && desktop.received("it-phone")
                    && phone.received("it-desktop")
                    && phone.received("it-phone")
            }),
            "both clients see input from both sides"
        );

        // Metadata follows the inner process: title and cwd.
        desktop.send("printf '\\033]0;it-title\\007'\n");
        assert!(
            wait_for(|| listed()
                .first()
                .is_some_and(|p| p.metadata.title == "it-title")),
            "pane title follows the inner process"
        );
        phone.send("cd elsewhere\n");
        let target = elsewhere.to_str().expect("utf-8 cwd").to_string();
        assert!(
            wait_for(|| listed()
                .first()
                .is_some_and(|p| p.metadata.current_path == target)),
            "pane cwd follows the inner process"
        );

        // Detaching one client keeps Pi and the other client intact. The
        // client name differs across tmux releases (tty path on 3.7,
        // client-<pid> on 3.3a), so select by client_pid and use that
        // record's own name as the target.
        let phone_name =
            client_name_by_pid(&socket.name, &name, phone.pid()).expect("phone client is listed");
        let detach = tmux_output(&socket.name, &["detach-client", "-t", &phone_name]);
        assert!(
            detach.status.success(),
            "detach failed: {}",
            String::from_utf8_lossy(&detach.stderr)
        );
        assert!(wait_for(|| phone.exited()), "detached client exits");
        assert!(
            wait_for(|| client_count(&socket.name, &name) == 1),
            "one client remains after the detach"
        );
        assert!(
            process_exists(pane_pid),
            "inner process survives the detach"
        );
        desktop.send("echo it-after-detach\n");
        assert!(
            wait_for(|| desktop.received("it-after-detach")),
            "remaining client still drives Pi"
        );

        // Attaching again works while the session is live.
        let mut second = AttachedClient::spawn(&attach_commands[0], 90, 26);
        assert!(
            wait_for(|| client_count(&socket.name, &name) == 2),
            "reattach after the detach"
        );
        desktop.send("echo it-again\n");
        assert!(
            wait_for(|| second.received("it-again")),
            "new client sees Pi output"
        );

        // Explicit termination ends Pi and every attached client.
        client
            .terminate_session("pi", &session_id)
            .expect("terminate");
        assert!(
            wait_for(|| !process_exists(pane_pid)),
            "inner process is gone"
        );
        assert!(
            wait_for(|| desktop.exited() && second.exited()),
            "all attached clients exit with the session"
        );
        assert!(
            wait_for(|| client.list_sessions().unwrap_or_default().is_empty()),
            "listing is empty after termination"
        );
    }
}
