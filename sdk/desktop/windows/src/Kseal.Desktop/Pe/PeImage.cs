using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Kseal.Desktop.Pe;

/// <summary>A parsed PE section header (name + raw-data location in the file).</summary>
public sealed record PeSection(string Name, uint RawAddress, uint RawSize, uint VirtualSize);

/// <summary>
/// Minimal, pure-managed PE (Portable Executable) parser for on-device integrity
/// checks. Validates the DOS/NT/optional-header structure, locates the
/// Authenticode certificate table (security data directory), and exposes section
/// headers so the integrity probe can detect a stripped signature, a malformed
/// image, or a tampered section.
///
/// Parsing operates on the raw file bytes — no Win32 dependency — so it is fully
/// unit-testable on any host. Every read is bounds-checked: a truncated or
/// inconsistent image parses to <see cref="IsValid"/> == false rather than
/// throwing or reading out of bounds.
/// </summary>
public sealed class PeImage
{
    private const ushort DosMagic = 0x5A4D;       // "MZ"
    private const uint PeSignature = 0x0000_4550; // "PE\0\0"
    private const ushort Pe32Magic = 0x10B;
    private const ushort Pe32PlusMagic = 0x20B;
    private const int CertificateDirectoryIndex = 4; // IMAGE_DIRECTORY_ENTRY_SECURITY

    private readonly byte[] _bytes;

    private const ushort WinCertTypePkcsSignedData = 0x0002; // WIN_CERT_TYPE_PKCS_SIGNED_DATA
    private const int WinCertificateHeaderSize = 8;          // dwLength + wRevision + wCertificateType

    public bool IsValid { get; private set; }
    public bool HasEmbeddedSignature { get; private set; }
    public uint CertificateTableSize { get; private set; }
    private uint _certificateTableOffset;
    public IReadOnlyList<PeSection> Sections { get; private set; } = [];

    private PeImage(byte[] bytes) => _bytes = bytes;

    /// <summary>Parses <paramref name="bytes"/>; the result's <see cref="IsValid"/> reports success.</summary>
    public static PeImage Parse(byte[] bytes)
    {
        var image = new PeImage(bytes);
        image.IsValid = image.TryParse();
        return image;
    }

    private bool TryParse()
    {
        var span = _bytes.AsSpan();
        if (span.Length < 64 || BinaryPrimitives.ReadUInt16LittleEndian(span) != DosMagic)
        {
            return false;
        }

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(0x3C, 4));
        // PE signature (4) + COFF header (20) + at least the standard optional header fields.
        if (peOffset < 0 || peOffset + 24 > span.Length)
        {
            return false;
        }
        if (BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(peOffset, 4)) != PeSignature)
        {
            return false;
        }

        int coff = peOffset + 4;
        ushort numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(coff + 2, 2));
        ushort sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(coff + 16, 2));
        int optionalHeader = coff + 20;
        if (optionalHeader + sizeOfOptionalHeader > span.Length || sizeOfOptionalHeader < 2)
        {
            return false;
        }

        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(optionalHeader, 2));
        // The data-directory array starts at a magic-dependent offset within the
        // optional header (PE32 vs PE32+ differ by the 8-byte ImageBase width).
        int dataDirOffset = magic switch
        {
            Pe32Magic => optionalHeader + 96,
            Pe32PlusMagic => optionalHeader + 112,
            _ => -1,
        };
        if (dataDirOffset < 0)
        {
            return false;
        }

        int certEntry = dataDirOffset + CertificateDirectoryIndex * 8;
        if (certEntry + 8 <= span.Length)
        {
            // The SECURITY directory's "VirtualAddress" is a raw file offset (not
            // an RVA) pointing at the WIN_CERTIFICATE attribute-certificate table.
            _certificateTableOffset = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(certEntry, 4));
            CertificateTableSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(certEntry + 4, 4));
            HasEmbeddedSignature = CertificateTableSize > 0;
        }

        int sectionTable = optionalHeader + sizeOfOptionalHeader;
        const int sectionHeaderSize = 40;
        if (sectionTable + numberOfSections * sectionHeaderSize > span.Length)
        {
            return false;
        }

        var sections = new List<PeSection>(numberOfSections);
        for (int i = 0; i < numberOfSections; i++)
        {
            int header = sectionTable + i * sectionHeaderSize;
            string name = ReadSectionName(span.Slice(header, 8));
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(header + 8, 4));
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(header + 16, 4));
            uint rawAddress = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(header + 20, 4));
            // A section whose raw bytes fall outside the file is a malformed image.
            if (rawSize != 0 && (long)rawAddress + rawSize > span.Length)
            {
                return false;
            }
            sections.Add(new PeSection(name, rawAddress, rawSize, virtualSize));
        }

        Sections = sections;
        return true;
    }

    private static string ReadSectionName(ReadOnlySpan<byte> raw)
    {
        int length = raw.IndexOf((byte)0);
        if (length < 0) length = raw.Length;
        return System.Text.Encoding.ASCII.GetString(raw[..length]);
    }

    /// <summary>
    /// Extracts the DER PKCS#7 <c>SignedData</c> blob from the first
    /// WIN_CERTIFICATE entry of the attribute-certificate table, or null when the
    /// image is unsigned, malformed, or the entry is not a PKCS#7 signature.
    /// </summary>
    public byte[]? EmbeddedPkcs7()
    {
        if (!IsValid || !HasEmbeddedSignature || _certificateTableOffset == 0) return null;
        var span = _bytes.AsSpan();
        long offset = _certificateTableOffset;
        if (offset + WinCertificateHeaderSize > span.Length) return null;

        uint dwLength = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)offset, 4));
        ushort certType = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)offset + 6, 2));
        if (certType != WinCertTypePkcsSignedData) return null;
        if (dwLength <= WinCertificateHeaderSize || offset + dwLength > span.Length) return null;

        int certLength = (int)dwLength - WinCertificateHeaderSize;
        return span.Slice((int)offset + WinCertificateHeaderSize, certLength).ToArray();
    }

    /// <summary>
    /// SHA-256 of a named section's raw bytes, or null when the section is absent
    /// or the image is invalid. Used to detect in-file modification of a known
    /// section (e.g. <c>.text</c>) against a signed-config baseline.
    /// </summary>
    public string? SectionSha256(string name)
    {
        if (!IsValid) return null;
        foreach (var section in Sections)
        {
            if (section.Name != name) continue;
            int size = (int)section.RawSize;
            int offset = (int)section.RawAddress;
            if (size == 0 || (long)offset + size > _bytes.Length) return null;
            byte[] hash = SHA256.HashData(_bytes.AsSpan(offset, size));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        return null;
    }
}
