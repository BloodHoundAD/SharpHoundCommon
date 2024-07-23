using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHoundCommonLib;

public static class AsyncEnumerable {
    public static IAsyncEnumerable<T> Empty<T>() => EmptyAsyncEnumerable<T>.Instance;
    
    private sealed class EmptyAsyncEnumerable<T> : IAsyncEnumerable<T> {
        public static readonly EmptyAsyncEnumerable<T> Instance = new();
        private readonly IAsyncEnumerator<T> _enumerator = new EmptyAsyncEnumerator<T>(); 
        public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = new CancellationToken()) {
            return _enumerator;
        }
    }

    private sealed class EmptyAsyncEnumerator<T> : IAsyncEnumerator<T> {
        public ValueTask DisposeAsync() => default;
        public ValueTask<bool> MoveNextAsync() => new(false);
        public T Current => default;
    }
}