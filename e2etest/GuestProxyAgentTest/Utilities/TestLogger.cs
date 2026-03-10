namespace GuestProxyAgentTest.Utilities
{
    public class TestLogger
    {
        public TestLogger(string prefix)
        {
            this.Prefix = prefix;
        }

        public string Prefix { get; }

        public void Log(string message)
        {
            Console.WriteLine($"[{this.Prefix}] - {DateTime.Now:yyyy-MM-ddTHH:mm:ss.fff} - {message}");
        }
    }
}
