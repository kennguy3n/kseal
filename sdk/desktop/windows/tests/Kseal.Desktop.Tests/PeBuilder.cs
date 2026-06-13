using System.Buffers.Binary;
using System.Text;

namespace Kseal.Desktop.Tests;

/// <summary>
/// Builds minimal but structurally valid PE32+ images for parser tests: a DOS
/// header, the NT/optional header with a 16-entry data directory (so the
/// certificate-table entry exists), and the requested sections with raw data.
/// </summary>
internal static class PeBuilder
{
    private const int PeOffset = 0x80;
    private const int SizeOfOptionalHeader = 240; // 112 standard + 16*8 data dirs
    private const int SectionHeaderSize = 40;
    private const ushort Pe32PlusMagic = 0x20B;

    public static byte[] Build(IReadOnlyList<(string Name, byte[] Data)> sections, uint certTableSize = 0x200)
    {
        int coff = PeOffset + 4;
        int optionalHeader = coff + 20;
        int sectionTable = optionalHeader + SizeOfOptionalHeader;
        int rawStart = sectionTable + sections.Count * SectionHeaderSize;

        int total = rawStart + sections.Sum(s => s.Data.Length);
        var buf = new byte[total];
        var span = buf.AsSpan();

        // DOS header.
        BinaryPrimitives.WriteUInt16LittleEndian(span, 0x5A4D); // MZ
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(0x3C, 4), PeOffset);

        // PE signature + COFF header.
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(PeOffset, 4), 0x0000_4550); // PE\0\0
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(coff + 2, 2), (ushort)sections.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(coff + 16, 2), SizeOfOptionalHeader);

        // Optional header magic + certificate data directory (index 4).
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(optionalHeader, 2), Pe32PlusMagic);
        int dataDir = optionalHeader + 112;
        int certEntry = dataDir + 4 * 8;
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(certEntry, 4), certTableSize > 0 ? 0x1000u : 0u); // RVA
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(certEntry + 4, 4), certTableSize);

        // Section headers + raw data.
        int offset = rawStart;
        for (int i = 0; i < sections.Count; i++)
        {
            var (name, data) = sections[i];
            int header = sectionTable + i * SectionHeaderSize;
            byte[] nameBytes = Encoding.ASCII.GetBytes(name);
            Array.Copy(nameBytes, 0, buf, header, Math.Min(8, nameBytes.Length));
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(header + 8, 4), (uint)data.Length);  // VirtualSize
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(header + 12, 4), 0x1000u * (uint)(i + 1)); // VirtualAddress
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(header + 16, 4), (uint)data.Length);  // SizeOfRawData
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(header + 20, 4), (uint)offset);        // PointerToRawData
            Array.Copy(data, 0, buf, offset, data.Length);
            offset += data.Length;
        }

        return buf;
    }

    public static byte[] BuildText(byte[] textBytes, uint certTableSize = 0x200) =>
        Build([(".text", textBytes)], certTableSize);

    /// <summary>
    /// Builds a PE32+ image whose SECURITY directory points at a real
    /// WIN_CERTIFICATE attribute-certificate table wrapping <paramref name="pkcs7"/>
    /// (type WIN_CERT_TYPE_PKCS_SIGNED_DATA), appended after the sections — so
    /// <see cref="PeImage.EmbeddedPkcs7"/> can extract the original blob.
    /// </summary>
    public static byte[] BuildWithCertificate(byte[] pkcs7, ushort certType = 0x0002)
    {
        byte[] text = [1, 2, 3, 4];
        byte[] image = BuildText(text, certTableSize: 0); // no directory yet; patched below

        int coff = PeOffset + 4;
        int optionalHeader = coff + 20;
        int dataDir = optionalHeader + 112;
        int certEntry = dataDir + 4 * 8;

        const int winCertHeader = 8; // dwLength + wRevision + wCertificateType
        uint dwLength = (uint)(winCertHeader + pkcs7.Length);
        int certOffset = image.Length;

        var buf = new byte[certOffset + (int)dwLength];
        Array.Copy(image, buf, image.Length);
        var span = buf.AsSpan();

        // Patch the SECURITY data directory: VirtualAddress is a raw file offset.
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(certEntry, 4), (uint)certOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(certEntry + 4, 4), dwLength);

        // WIN_CERTIFICATE { DWORD dwLength; WORD wRevision; WORD wCertificateType; BYTE bCert[]; }
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(certOffset, 4), dwLength);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(certOffset + 4, 2), 0x0200); // WIN_CERT_REVISION_2_0
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(certOffset + 6, 2), certType);
        Array.Copy(pkcs7, 0, buf, certOffset + winCertHeader, pkcs7.Length);

        return buf;
    }
}
