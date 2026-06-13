namespace Kseal.Desktop;

/// <summary>Optional initialization knobs. Defaults keep launch network-free and the footprint small.</summary>
public sealed record KsealDesktopOptions
{
    /// <summary>Ed25519 public key (32 bytes) used to verify signed configs.</summary>
    public byte[] ConfigPublicKey { get; init; } = new byte[32];

    /// <summary>Content hash of the protected build.</summary>
    public string BuildHash { get; init; } = "";

    /// <summary>Expected code-signing baseline for the integrity probes.</summary>
    public WindowsIntegrityPolicy IntegrityPolicy { get; init; } = new();

    /// <summary>Probe ids to run; null runs the default desktop set (everything except the opt-in debugger probe).</summary>
    public IReadOnlySet<string>? EnabledProbes { get; init; }

    /// <summary>Telemetry events buffered before a batch is flushed.</summary>
    public int MaxBatchEvents { get; init; } = 32;
}

/// <summary>
/// Public entry point to the kseal <b>Windows</b> desktop SDK.
///
/// Wraps the shared Rust trust core (via P/Invoke to the C ABI) and the native
/// Windows integrity probes (Authenticode, PE integrity, DLL injection). The SDK
/// gathers local integrity signals, hands the packed risk bitset to the core for
/// scoring, drives the server trust flow, and produces per-request proofs — but
/// never makes the final trust decision (the server does). It performs <b>no
/// network I/O at launch</b>: probes run lazily on demand, telemetry is batched,
/// and the trust session is established only when the host calls
/// <see cref="EstablishTrustSession"/>.
/// </summary>
public sealed class KsealDesktopClient : IDisposable
{
    private readonly ITrustCore _core;
    private readonly IWindowsEnvironment _env;
    private readonly KsealDesktopOptions _options;
    private readonly IConfigProvider _configProvider;
    private readonly ITelemetrySink _telemetrySink;
    private readonly ICodeIntegrityAttestor _attestor;
    private readonly string _installIdentityHash;
    private readonly IClock _clock;
    private readonly IReadOnlyList<IProbe> _probes;

    private readonly object _gate = new();
    private readonly List<byte[]> _pendingEvents = [];
    private long _sequence;
    private string? _trustTokenId;
    private string _policyHash = "";

    private const int NonceLength = 16;

    internal KsealDesktopClient(
        ITrustCore core,
        IWindowsEnvironment env,
        KsealDesktopOptions options,
        IConfigProvider configProvider,
        ITelemetrySink telemetrySink,
        ICodeIntegrityAttestor attestor,
        string installIdentityHash,
        IClock clock)
    {
        _core = core;
        _env = env;
        _options = options;
        _configProvider = configProvider;
        _telemetrySink = telemetrySink;
        _attestor = attestor;
        _installIdentityHash = installIdentityHash;
        _clock = clock;
        _probes = BuildProbes(env, options);
    }

    /// <summary>The Rust trust core version string.</summary>
    public string CoreVersion => _core.Version;

    /// <summary>The stable, tenant-scoped install identity hash (non-PII) bound to the trust session.</summary>
    public string InstanceId => _installIdentityHash;

    /// <summary>Sets the trust-token id minted by the server; request proofs bind to it.</summary>
    public void SetTrustToken(string tokenId)
    {
        lock (_gate) { _trustTokenId = tokenId; }
    }

    /// <summary>Runs the enabled probes and asks the core to score the result.</summary>
    public RiskAssessment EvaluateRisk()
    {
        var signals = RunProbes();
        ulong bits = RiskSignals.Pack(signals);
        var (score, level) = _core.EvaluateRiskAndLevel(bits);
        return new RiskAssessment(bits, signals, score.Score, score.Confidence, level);
    }

    /// <summary>
    /// Establishes a trust session against the server: fetch nonce, evaluate
    /// local integrity, build the platform attestation, and verify. On success
    /// the minted trust token is stored so <see cref="GetRequestProof"/> can bind
    /// to it. This is the only network call the SDK initiates, and never at launch.
    /// </summary>
    public TrustSession EstablishTrustSession(ITrustSessionClient client)
    {
        byte[] nonce = client.GetNonce();
        ulong bits = RiskSignals.Pack(RunProbes());
        AuthenticodeInfo info = _env.VerifyAuthenticode();
        byte[] token = _attestor.AttestationToken(info);

        TrustSession session = client.VerifyAttestation(
            nonce, bits, _options.BuildHash, CurrentPolicyHash(), _installIdentityHash, token);
        if (session.Accepted && !string.IsNullOrEmpty(session.TokenId))
        {
            SetTrustToken(session.TokenId);
        }
        return session;
    }

    /// <summary>
    /// Builds a per-request proof binding <paramref name="requestHash"/> to the
    /// current trust token using a fresh nonce and a strictly increasing sequence
    /// number.
    /// </summary>
    public RequestProof GetRequestProof(byte[] requestHash)
    {
        string token;
        long seq;
        lock (_gate)
        {
            if (_trustTokenId is null)
            {
                throw new TrustCoreException("no trust token set; call EstablishTrustSession() or SetTrustToken()");
            }
            token = _trustTokenId;
            seq = ++_sequence;
        }

        byte[] nonce = _core.GenerateNonce(NonceLength);
        byte[] proofBytes = _core.GenerateRequestProof(token, requestHash, nonce, seq);
        return new RequestProof(token, requestHash, nonce, seq, proofBytes);
    }

    /// <summary>Builds a request proof and asks the server to validate it (ALLOW / STEP_UP / DENY).</summary>
    public RequestProofDecision AuthorizeRequest(byte[] requestHash, ITrustSessionClient client)
    {
        RequestProof proof = GetRequestProof(requestHash);
        return client.ValidateRequestProof(proof);
    }

    /// <summary>
    /// Records a telemetry event, buffering it; a batch is compressed and handed
    /// to the sink once <c>MaxBatchEvents</c> is reached. The event carries only
    /// the packed risk bitset and coarse metadata — no PII.
    /// </summary>
    public void ReportEvent(EventType eventType)
    {
        ulong bits = RiskSignals.Pack(RunProbes());
        byte[]? evt = TryMakeEvent(eventType, bits);
        if (evt is null) return;

        byte[][]? toFlush = null;
        lock (_gate)
        {
            _pendingEvents.Add(evt);
            if (_pendingEvents.Count >= _options.MaxBatchEvents)
            {
                toFlush = [.. _pendingEvents];
                _pendingEvents.Clear();
            }
        }
        if (toFlush is not null) Emit(toFlush);
    }

    /// <summary>Forces any buffered telemetry to be compressed and sent.</summary>
    public void FlushTelemetry()
    {
        byte[][] toFlush;
        lock (_gate)
        {
            if (_pendingEvents.Count == 0) return;
            toFlush = [.. _pendingEvents];
            _pendingEvents.Clear();
        }
        Emit(toFlush);
    }

    /// <summary>Re-fetches and verifies the signed config (on demand — never at launch).</summary>
    public bool RefreshConfig()
    {
        byte[]? bytes = _configProvider.FetchConfig() ?? _configProvider.CachedConfig();
        if (bytes is null || !_core.TryLoadConfig(bytes)) return false;
        _configProvider.Persist(bytes);
        return true;
    }

    /// <summary>Reports a TLS pinning failure observed by the host's transport layer.</summary>
    public void ReportPinningFailure()
    {
        ulong bits = RiskSignal.PinningFailure.Mask() | RiskSignal.NetworkMitm.Mask();
        byte[]? evt = TryMakeEvent(EventType.NetworkMitm, bits);
        if (evt is not null) Emit([evt]);
    }

    private string CurrentPolicyHash()
    {
        lock (_gate) { return _policyHash; }
    }

    private byte[]? TryMakeEvent(EventType eventType, ulong bits)
    {
        try
        {
            CoreRiskScore score = _core.EvaluateRisk(bits);
            return _core.CreateEvent(
                eventType, bits, score.Confidence,
                _options.BuildHash, CurrentPolicyHash(), _installIdentityHash, CoarseTimeBucket(), country: null);
        }
        catch (TrustCoreException)
        {
            return null;
        }
    }

    private void Emit(IReadOnlyList<byte[]> events)
    {
        if (events.Count == 0) return;
        try
        {
            byte[] wire = _core.BatchAndCompress(events);
            if (wire.Length > 0) _telemetrySink.Send(wire);
        }
        catch (TrustCoreException)
        {
            // Drop the batch rather than crash the host; telemetry is best-effort.
        }
    }

    private IReadOnlySet<RiskSignal> RunProbes()
    {
        var signals = new HashSet<RiskSignal>();
        foreach (var probe in _probes) signals.UnionWith(probe.Evaluate());
        return signals;
    }

    private long CoarseTimeBucket()
    {
        const long hourMillis = 3_600_000;
        return _clock.NowMillis() / hourMillis * hourMillis;
    }

    private static IReadOnlyList<IProbe> BuildProbes(IWindowsEnvironment env, KsealDesktopOptions options)
    {
        var policy = options.IntegrityPolicy;
        IProbe[] all =
        [
            new AuthenticodeProbe(env, policy),
            new PeIntegrityProbe(env, policy),
            new DllInjectionProbe(env),
            new DebuggerProbe(env),
        ];
        // Default desktop set omits the aggressive anti-debug probe; the host opts
        // in explicitly (see ARCHITECTURE.md desktop caution).
        IEnumerable<IProbe> selected = options.EnabledProbes is { } enabled
            ? all.Where(p => enabled.Contains(p.Id))
            : all.Where(p => p.Id != "windows.debugger");
        return [.. selected];
    }

    public void Dispose() => _core.Dispose();

    // --- Lifecycle ---

    private static readonly object SingletonGate = new();
    private static KsealDesktopClient? _instance;

    /// <summary>The initialized singleton, or null if <see cref="Initialize"/> has not run.</summary>
    public static KsealDesktopClient? Shared
    {
        get { lock (SingletonGate) { return _instance; } }
    }

    /// <summary>
    /// Initializes the SDK: loads any cached signed config and brings up the Rust
    /// trust core. Safe to call once at app start; subsequent calls return the
    /// existing instance. Performs no network I/O.
    /// </summary>
    public static KsealDesktopClient Initialize(
        string tenantId,
        string appId,
        KsealDesktopOptions? options = null,
        ICodeIntegrityAttestor? attestor = null)
    {
        lock (SingletonGate)
        {
            if (_instance is not null) return _instance;

            var opts = options ?? new KsealDesktopOptions();
            string storageDir = StorageDirectory();
            var env = DesktopEnvironmentFactory.Create();
            byte[] proofKey = new DefaultProofKeyProvider(storageDir).ProofKey();
            var core = NativeTrustCore.Create(
                opts.ConfigPublicKey, proofKey, Platform.Unspecified, opts.MaxBatchEvents);
            var configProvider = new FileConfigProvider(storageDir);
            string installHash = new InstallIdentity(storageDir).TenantScopedHash(tenantId, appId);

            var sdk = new KsealDesktopClient(
                core, env, opts, configProvider, new BufferingTelemetrySink(),
                attestor ?? new LocalCodeIntegrityAttestor(), installHash, new SystemClock());

            byte[]? cached = configProvider.CachedConfig();
            if (cached is not null) core.TryLoadConfig(cached);

            _instance = sdk;
            return sdk;
        }
    }

    /// <summary>Releases the singleton (primarily for tests / process teardown).</summary>
    public static void ShutdownForTesting()
    {
        lock (SingletonGate)
        {
            _instance?.Dispose();
            _instance = null;
        }
    }

    private static string StorageDirectory()
    {
        string baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(baseDir)) baseDir = Path.GetTempPath();
        return baseDir;
    }
}
