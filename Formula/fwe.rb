# fwe for Homebrew, from this repository as a tap:
#
#   brew tap e6qu/fwe https://github.com/e6qu/fun-with-emulators
#   brew install fwe          # the latest release
#   brew install --HEAD fwe   # main
#
# Built from source and signed for this Mac (ad hoc) with the entitlements
# the VM backend and the hardened runtime need (hypervisor.entitlements).
class Fwe < Formula
  desc "Run Linux arm64 programs natively on macOS"
  homepage "https://github.com/e6qu/fun-with-emulators"
  url "https://github.com/e6qu/fun-with-emulators/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "RELEASE_SHA256"
  license "MIT"
  head "https://github.com/e6qu/fun-with-emulators.git", branch: "main"

  depends_on "rust" => :build
  depends_on arch: :arm64
  depends_on :macos

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/fwe")
    system "codesign", "--sign", "-", "--force", "--options", "runtime",
           "--entitlements", "hypervisor.entitlements", bin/"fwe"
  end

  test do
    assert_match "fwe ", shell_output("#{bin}/fwe --version")
    # A static Linux program: guests/asm/hello.S, assembled and linked as the
    # repository's tests do. It writes a line and exits.
    hello = testpath/"hello"
    hello.binwrite <<~EOS.unpack1("m")
      f0VMRgIBAQAAAAAAAAAAAAIAtwABAAAANAEBAAABAABAAAAAAAAAAKgCAAAAAAAAAAAAAEAA
      OAAEAEAABwAFAAYAAAAEAAAAQAAAAAAAAABAAAAAAAEAAEAAAAAAAQAA4AAAAAAAAADgAAAA
      AAAAAAgAAAAAAAAAAQAAAAQAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAxAQAAAAAAADEB
      AAAAAAAAAAABAAAAAAABAAAABQAAADQBAAAAAAAANAEBAAABAAA0AQEAAAEAACAAAAAAAAAA
      IAAAAAAAAAAAAAEAAAAAAFHldGQGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      AAAAAAAAAAAAAAAAAAAAAAAAaGVsbG8gZnJvbSBsaW51eAoAAAAgAIDSQf/3ECICgNIICIDS
      AQAA1AAAgNLIC4DSAQAA1ExpbmtlcjogTExEIDIzLjEuNSAoaHR0cHM6Ly9naXRodWIuY29t
      L3J1c3QtbGFuZy9sbHZtLXByb2plY3QuZ2l0IDBhNTU3OWViNjQ5ZDM2MzRhOWMzMGFjODcz
      MzAwY2MyOTQ0ZmEwNzApAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAIANAEBAAAB
      AAAAAAAAAAAAAAQAAAAAAAEAIAEAAAABAAAAAAAAAAAAAAwAAAAAAAEAMQEAAAABAAAAAAAA
      AAAAABgAAAAAAAEAIAEAAAABAAAAAAAAAAAAABsAAAAQAAIANAEBAAABAAAAAAAAAAAAAAAu
      cm9kYXRhAC50ZXh0AC5jb21tZW50AC5zeW10YWIALnNoc3RydGFiAC5zdHJ0YWIAACR4AG1l
      c3NhZ2UAbWVzc2FnZV9lbmQAJGQAX3N0YXJ0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAACAAAA
      AAAAACABAAAAAQAAIAEAAAAAAAARAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAkA
      AAABAAAABgAAAAAAAAA0AQEAAAEAADQBAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAA
      AAAAAAAAAAAPAAAAAQAAADAAAAAAAAAAAAAAAAAAAABUAQAAAAAAAGwAAAAAAAAAAAAAAAAA
      AAABAAAAAAAAAAEAAAAAAAAAGAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAwAEAAAAAAACQAAAA
      AAAAAAYAAAAFAAAACAAAAAAAAAAYAAAAAAAAACAAAAADAAAAAAAAAAAAAAAAAAAAAAAAAFAC
      AAAAAAAAMgAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAqAAAAAwAAAAAAAAAAAAAA
      AAAAAAAAAACCAgAAAAAAACIAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAA
    EOS
    hello.chmod 0755
    assert_equal "hello from linux\n", shell_output("#{bin}/fwe #{hello}")
  end
end
