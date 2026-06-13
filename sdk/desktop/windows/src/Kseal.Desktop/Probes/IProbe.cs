namespace Kseal.Desktop;

/// <summary>A risk-signal source. Probes are cheap, side-effect-free, and never block on I/O.</summary>
public interface IProbe
{
    string Id { get; }
    IReadOnlySet<RiskSignal> Evaluate();
}
