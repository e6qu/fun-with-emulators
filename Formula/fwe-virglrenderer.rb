# virglrenderer for fwe's GPU device, from this repository as a tap:
#
#   brew tap e6qu/fwe https://github.com/e6qu/fun-with-emulators
#   brew install fwe-virglrenderer
#
# Upstream virglrenderer's Venus renderer, built for macOS: Vulkan's
# commands, as Mesa's Venus driver writes them in a Linux program, run on
# MoltenVK (Metal). fwe's GPU helper loads it from this formula's prefix
# (or as FWE_VIRGLRENDERER names it). Only Venus is built (no OpenGL
# renderer), its render server a thread of the helper's.
class FweVirglrenderer < Formula
  include Language::Python::Virtualenv

  desc "Venus Vulkan renderer of virglrenderer, for fwe's GPU device"
  homepage "https://gitlab.freedesktop.org/virgl/virglrenderer"
  url "https://gitlab.freedesktop.org/virgl/virglrenderer/-/archive/8f6c5eebee094f64ef1a126e5072481a414e6a9c/virglrenderer-8f6c5eebee094f64ef1a126e5072481a414e6a9c.tar.gz"
  version "1.3.0.20261124"
  sha256 "f7d006ad8adc1e77b09058e78a09b46f9c8176afc6638b19cceeb54ac9b446cf"
  license "MIT"

  keg_only "it is fwe's build of a library other formulae provide"

  depends_on "meson" => :build
  depends_on "ninja" => :build
  depends_on "pkgconf" => :build
  depends_on "python@3.14" => :build
  depends_on "vulkan-headers" => :build
  depends_on arch: :arm64
  depends_on :macos
  depends_on "molten-vk"
  depends_on "vulkan-loader"

  # The protocol's headers, which virglrenderer's build would fetch with
  # git (its wrap), generated at build time with Mako.
  resource "venus-protocol" do
    url "https://gitlab.freedesktop.org/virgl/venus-protocol/-/archive/v1.1.3/venus-protocol-v1.1.3.tar.gz"
    sha256 "c5a362ca28e0a35042db1baeadaf9183500b216841e49d72714b80bae50b4445"
  end

  resource "mako" do
    url "https://files.pythonhosted.org/packages/5a/09/e07c4b5579a79f4b16f8d4f29f6c54514ac787c4ad506b8c4f28a0e6b0bf/mako-1.4.3.tar.gz"
    sha256 "cd6537fe88d5fec315c55c2f8529bc4ce7a9a352ad7db3eeaa6a66e2dd4ec37a"
  end

  resource "markupsafe" do
    url "https://files.pythonhosted.org/packages/38/9b/e422a865e1d5d57d0e509b4e0bf1c1a70a7f6382c29a5aa428df994c8bc8/markupsafe-3.0.4.tar.gz"
    sha256 "2e9ad7dd851bf45fab9f75cbff4cb493fee9979e8d8c7c9c3ee119022518edd6"
  end

  def install
    python = Formula["python@3.14"].opt_libexec/"bin/python3"
    venv = virtualenv_create(buildpath/"venv", python)
    venv.pip_install resources.reject { |r| r.name == "venus-protocol" }
    ENV.prepend_path "PATH", buildpath/"venv/bin"

    # The wrap's directory, so meson uses it in place of a git checkout.
    (buildpath/"subprojects/venus-protocol-1.1.3").install resource("venus-protocol")

    args = %w[
      -Dvenus=true
      -Dvrend=false
      -Drender-server-mode=thread
      -Drender-server-worker=thread
      -Dvulkan-dload=false
      -Dtests=false
      -Dvenus-protocol:werror=false
      --force-fallback-for=venus-protocol
      --wrap-mode=nodownload
    ]
    system "meson", "setup", "build", *args, *std_meson_args
    system "meson", "compile", "-C", "build", "--verbose"
    system "meson", "install", "-C", "build"
  end

  test do
    # The entry points fwe's GPU helper calls.
    symbols = shell_output("nm -gU #{lib}/libvirglrenderer.1.dylib")
    %w[
      virgl_renderer_init virgl_renderer_get_cap_set virgl_renderer_fill_caps
      virgl_renderer_context_create_with_flags virgl_renderer_context_destroy
      virgl_renderer_submit_cmd virgl_renderer_resource_create_blob
      virgl_renderer_resource_export_blob virgl_renderer_resource_unref
      virgl_renderer_ctx_attach_resource virgl_renderer_ctx_detach_resource
      virgl_renderer_context_create_fence
    ].each { |s| assert_match "_#{s}\n", symbols }
  end
end
