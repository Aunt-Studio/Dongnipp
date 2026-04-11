using Microsoft.Extensions.Caching.Memory;
internal static class InternalCacheProvider
{
    private static readonly MemoryCache _cache = new MemoryCache(new MemoryCacheOptions());

    public static IMemoryCache Cache => _cache;
}
