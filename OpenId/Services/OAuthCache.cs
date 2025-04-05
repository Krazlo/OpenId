namespace OpenId.Services
{
    public static class OAuthCache
    {
        private static readonly Dictionary<string, string> _verifiers = new();

        public static void StoreCodeVerifier(string state, string codeVerifier)
        {
            _verifiers[state] = codeVerifier;
        }

        public static string? GetCodeVerifier(string state)
        {
            return _verifiers.TryGetValue(state, out var verifier) ? verifier : null;
        }
    }
}
