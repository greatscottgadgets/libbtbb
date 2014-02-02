require 'formula'

class Libbtbb < Formula
  homepage 'https://github.com/greatscottgadgets/libbtbb'
  url 'https://github.com/greatscottgadgets/libbtbb/archive/2014-02-R1.tar.gz'
  sha256 '91a0dafcb9911d6ca4959fdd8d2aaa5d2cfa76c9754757505898def08da7d5a3'
  version '2014-02-R1'

  head 'https://github.com/greatscottgadgets/libbtbb.git'

  option :universal

  depends_on 'cmake' => :build
  depends_on :python

  def install
    if build.universal?
      ENV.universal_binary
      ENV['CMAKE_OSX_ARCHITECTURES'] = Hardware::CPU.universal_archs.as_cmake_arch_flags
    end
    mkdir "build" do
      system "cmake", "..", *std_cmake_args
      system "make install"
    end
  end
end
