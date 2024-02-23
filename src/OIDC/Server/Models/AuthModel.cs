namespace Server.Models
{
    public class AuthCodeModel
    {
        public required string? ClientID { get; set; }

        public required string Nonce { get; set; }
        public required string? CodeChallenge { get; set; }

        //public required string? CodeChallengeMethod { get; set; }

        //public required string? RedirectUri { get; set; }

        public required DateTime Expriy { get; set; }

        public required string Scope { get; set; }
    }
}
