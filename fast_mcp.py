import sys
import hexstrike_mcp
try:
    def fast_init(self, server_url, timeout=300):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = __import__("requests").Session()
    hexstrike_mcp.HexStrikeClient.__init__ = fast_init
    hexstrike_mcp.HexStrikeClient.check_health = (
        lambda self: {"status": "healthy", "version": "6.0.0"}
    )
except AttributeError as e:
    print(
        f"[WARN] Monkey-patch failed (hexstrike_mcp API changed?): {e}",
        file=sys.stderr,
    )
if __name__ == "__main__":
    hexstrike_mcp.main()
