class Localenvx < Formula
  desc "A local encrypted .env manager."
  homepage "https://github.com/ctxinf/localenvx"
  url "https://github.com/ctxinf/localenvx.git", tag: "v0.5.0"
  license "MIT"
  head "https://github.com/ctxinf/localenvx.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "localenvx", shell_output("#{bin}/localenvx --version")
    assert_match "localenvx usage guide", shell_output("#{bin}/localenvx --skill")
  end
end
