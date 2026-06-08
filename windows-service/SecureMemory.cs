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

    private IntPtr _mem;
    private readonly int _sz;
    private readonly object _lk = new();
    private int _disposed;
    private bool _locked;
    private byte[]? _ek;
    private readonly bool _enc;

    public SecureMemory(int sz, bool lk = true, bool enc = true)
    {
        if (sz <= 0 || sz % 4096 != 0)
            throw new ArgumentException("Size must be a multiple of 4096");

        _sz = sz;
        _mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)_sz, MEM_RESERVE | MEM_COMMIT, PAGE_RW);
        if (_mem == IntPtr.Zero)
            throw new OutOfMemoryException($"VirtualAlloc failed: {Marshal.GetLastWin32Error()}");

        unsafe
        {
            byte* p = (byte*)_mem.ToPointer();
            for (int i = 0; i < _sz; i++) p[i] = 0;
        }

        if (lk) _locked = VirtualLock(_mem, (UIntPtr)_sz);
        if (enc) { _ek = new byte[32]; RandomNumberGenerator.Fill(_ek); _enc = true; }
    }

    public void Write(byte[] d, int o = 0)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(d);
        if (o < 0 || o + d.Length > _sz)
            throw new ArgumentOutOfRangeException();

        lock (_lk)
        {
            byte[] w = _enc && _ek != null ? Enc(d) : d;
            Marshal.Copy(w, 0, _mem + o, w.Length);
            if (w != d) CryptographicOperations.ZeroMemory(w);
        }
    }

    public byte[] Read(int o, int l)
    {
        ThrowIfDisposed();
        if (o < 0 || l < 0 || o + l > _sz)
            throw new ArgumentOutOfRangeException();

        lock (_lk)
        {
            byte[] b = new byte[l];
            Marshal.Copy(_mem + o, b, 0, l);
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
                    for (int i = 0; i < _sz; i++) p[i] = 0;
                }
                VirtualProtect(_mem, (UIntPtr)_sz, PAGE_NO, out _);
                if (_locked) VirtualUnlock(_mem, (UIntPtr)_sz);
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
        using var a = Aes.Create();
        a.Key = _ek!;
        a.Mode = CipherMode.CBC;
        a.Padding = PaddingMode.PKCS7;
        a.GenerateIV();
        using var e = a.CreateEncryptor();
        byte[] c = e.TransformFinalBlock(d, 0, d.Length);
        byte[] r = new byte[16 + c.Length];
        Buffer.BlockCopy(a.IV, 0, r, 0, 16);
        Buffer.BlockCopy(c, 0, r, 16, c.Length);
        return r;
    }

    private byte[] Dec(byte[] d)
    {
        byte[] iv = new byte[16], c = new byte[d.Length - 16];
        Buffer.BlockCopy(d, 0, iv, 0, 16);
        Buffer.BlockCopy(d, 16, c, 0, c.Length);
        using var a = Aes.Create();
        a.Key = _ek!;
        a.IV = iv;
        a.Mode = CipherMode.CBC;
        a.Padding = PaddingMode.PKCS7;
        using var dec = a.CreateDecryptor();
        return dec.TransformFinalBlock(c, 0, c.Length);
    }
}
