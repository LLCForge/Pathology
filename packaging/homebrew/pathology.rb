# Homebrew formula for Pathology.
# Rendered by sync.py; @VERSION@ and the @SHA256_*@ values are filled in by the
# release workflow (job "publish", step "Render package-manager manifests") and
# shipped in pathology-<version>-package-manifests.tar.gz. Copy the rendered file
# into the tap repository (LLCForge/homebrew-tap, Formula/pathology.rb).
class Pathology < Formula
  desc "BGP route monitor for your own routers: BMP and passive BGP collector, learned baselines, deviation alerts"
  homepage "https://github.com/LLCForge/Pathology"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/LLCForge/Pathology/releases/download/v@VERSION@/pathology-@VERSION@-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA256_AARCH64_APPLE_DARWIN@"
    end
    on_intel do
      url "https://github.com/LLCForge/Pathology/releases/download/v@VERSION@/pathology-@VERSION@-x86_64-apple-darwin.tar.gz"
      sha256 "@SHA256_X86_64_APPLE_DARWIN@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/LLCForge/Pathology/releases/download/v@VERSION@/pathology-@VERSION@-aarch64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_AARCH64_LINUX_MUSL@"
    end
    on_intel do
      url "https://github.com/LLCForge/Pathology/releases/download/v@VERSION@/pathology-@VERSION@-x86_64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_X86_64_LINUX_MUSL@"
    end
  end

  def install
    bin.install "pathology"
    pkgetc.install "pathology.example.toml" if File.exist?("pathology.example.toml")
    doc.install Dir["README*.md"]
  end

  service do
    run [opt_bin/"pathology", "run", "--config", etc/"pathology/pathology.toml"]
    environment_variables STATE_DIRECTORY: var/"lib/pathology"
    keep_alive successful_exit: false
    log_path var/"log/pathology.log"
    error_log_path var/"log/pathology.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pathology --version")
  end
end
