using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SovereignKernel.Service;

public sealed class SecureMemory : IDisposable
{
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr sz, uint type, uint prot);
    [DllImport("kernel32.dll")] private static extern bool VirtualFree(IntPtr addr, UIntPtr sz, uint type);
    [DllImport("kernel32.dll")] private static extern bool VirtualLock(IntPtr addr, UIntPtr sz);
    [DllImport("kernel32.dll")] private static extern bool VirtualUnlock(IntPtr addr, UIntPtr sz);
    [DllImport("kernel32.dll")] private static extern bool VirtualProtect(IntPtr addr, UIntPtr sz, uint np, out uint op);

    private const uint MEM_RESERVE = 0x2000, MEM_COMMIT = 0x1000, MEM_RELEASE = 0x8000;
    private const uint PAGE_RW = 0x04, PAGE_NO = 0x01;
    private const int GCM_NONCE_SIZE = 12;
    private const int GCM_TAG_SIZE = 16;

    private IntPtr _mem;
    private readonly int _sz;
    private readonly int _allocSz;
    private readonly object _lk = new();
    private int _disposed;
    private bool _locked;
    private byte[]? _ek;
    private readonly bool _enc;

    public SecureMemory(int sz, bool lk = true, bool enc = true)
    {
        if (sz <= 0)
            throw new ArgumentException("Size must be positive");

        _sz = sz;
        int overhead = enc ? GCM_NONCE_SIZE + GCM_TAG_SIZE : 0;
        int rawNeeded = sz + overhead;
        _allocSz = ((rawNeeded + 4095) / 4096) * 4096;

        _mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)_allocSz, MEM_RESERVE | MEM_COMMIT, PAGE_RW);
        if (_mem == IntPtr.Zero)
            throw new OutOfMemoryException($"VirtualAlloc failed: {Marshal.GetLastWin32Error()}");

        unsafe
        {
            byte* p = (byte*)_mem.ToPointer();
            for (int i = 0; i < _allocSz; i++) p[i] = 0;
        }

        if (lk) _locked = VirtualLock(_mem, (UIntPtr)_allocSz);
        if (enc)
        {
            _ek = new byte[32];
            RandomNumberGenerator.Fill(_ek);
            _enc = true;
        }
    }

    public void Write(byte[] d, int o = 0)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(d);
        if (o < 0 || d.Length > _sz || o + d.Length > _sz)
            throw new ArgumentOutOfRangeException(nameof(o), "Data overschrijdt beveiligde geheugengrens");

        lock (_lk)
        {
            byte[] w = _enc && _ek != null ? Enc(d) : d;
            if (w.Length > _allocSz)
                throw new InvalidOperationException("Versleutelde data overschrijdt allocatie — intern fout");
            Marshal.Copy(w, 0, _mem + o, w.Length);
            if (w != d) CryptographicOperations.ZeroMemory(w);
        }
    }

    public byte[] Read(int o, int l)
    {
        ThrowIfDisposed();
        if (o < 0 || l < 0 || l > _sz || o + l > _allocSz)
            throw new ArgumentOutOfRangeException();

        lock (_lk)
        {
            int readLen = _enc && _ek != null ? l + GCM_NONCE_SIZE + GCM_TAG_SIZE : l;
            if (o + readLen > _allocSz) readLen = _allocSz - o;
            byte[] b = new byte[readLen];
            Marshal.Copy(_mem + o, b, 0, readLen);
            return _enc && _ek != null ? Dec(b) : b;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        lock (_lk)
        {
            if (_mem != IntPtr.Zero)
            {
                unsafe
                {
                    byte* p = (byte*)_mem.ToPointer();
                    for (int i = 0; i < _allocSz; i++) p[i] = 0;
                }
                VirtualProtect(_mem, (UIntPtr)_allocSz, PAGE_NO, out _);
                if (_locked) VirtualUnlock(_mem, (UIntPtr)_allocSz);
                VirtualFree(_mem, UIntPtr.Zero, MEM_RELEASE);
                _mem = IntPtr.Zero;
            }
            if (_ek != null) { CryptographicOperations.ZeroMemory(_ek); _ek = null; }
        }
        GC.SuppressFinalize(this);
    }

    ~SecureMemory() => Dispose();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ThrowIfDisposed()
    {
        if (_disposed != 0) throw new ObjectDisposedException(nameof(SecureMemory));
    }

    private byte[] Enc(byte[] d)
    {
        byte[] nonce = new byte[GCM_NONCE_SIZE];
        RandomNumberGenerator.Fill(nonce);
        byte[] ciphertext = new byte[d.Length];
        byte[] tag = new byte[GCM_TAG_SIZE];
        using var aesGcm = new AesGcm(_ek!, GCM_TAG_SIZE);
        aesGcm.Encrypt(nonce, d, ciphertext, tag);
        byte[] result = new byte[GCM_NONCE_SIZE + ciphertext.Length + GCM_TAG_SIZE];
        Buffer.BlockCopy(nonce, 0, result, 0, GCM_NONCE_SIZE);
        Buffer.BlockCopy(ciphertext, 0, result, GCM_NONCE_SIZE, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, GCM_NONCE_SIZE + ciphertext.Length, GCM_TAG_SIZE);
        return result;
    }

    private byte[] Dec(byte[] d)
    {
        if (d.Length < GCM_NONCE_SIZE + GCM_TAG_SIZE)
            throw new CryptographicException("Data te kort voor AES-GCM decryptie");
        byte[] nonce = new byte[GCM_NONCE_SIZE];
        int cipherLen = d.Length - GCM_NONCE_SIZE - GCM_TAG_SIZE;
        byte[] ciphertext = new byte[cipherLen];
        byte[] tag = new byte[GCM_TAG_SIZE];
        Buffer.BlockCopy(d, 0, nonce, 0, GCM_NONCE_SIZE);
        Buffer.BlockCopy(d, GCM_NONCE_SIZE, ciphertext, 0, cipherLen);
        Buffer.BlockCopy(d, GCM_NONCE_SIZE + cipherLen, tag, 0, GCM_TAG_SIZE);
        byte[] plaintext = new byte[cipherLen];
        using var aesGcm = new AesGcm(_ek!, GCM_TAG_SIZE);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
