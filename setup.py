#!/usr/bin/python3
import os
import platform
import subprocess
import sys
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

name = "pylibjodi"


class CMakeExtension(Extension):
    def __init__(self, name, sourcedir=""):
        Extension.__init__(self, name, sources=["./"])
        self.sourcedir = os.path.abspath(sourcedir)


class CMakeBuild(build_ext):
    def run(self):
        try:
            subprocess.check_output(["cmake", "--version"])
        except OSError:
            raise RuntimeError(
                "CMake must be installed to build"
                + " the following extensions: "
                + ", ".join(e.name for e in self.extensions)
            )

        for ext in self.extensions:
            self.build_extension(ext)

    def build_extension(self, ext):
        extdir = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))
        cmake_args = [
            "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=" + extdir,
            "-DPYTHON_EXECUTABLE=" + sys.executable,
            "-DBUILD_LIBJODI_TESTS=OFF",
            "-DBUILD_LIBJODI_BENCHMARKS=OFF",
            "-DENABLE_SANITIZERS=OFF",
        ]

        cfg = "Release" #if self.debug else "Release"
        build_args = ["--config", cfg]

        if platform.system() == "Windows":
            cmake_args += [
                "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{}={}".format(cfg.upper(), extdir)
            ]
        else:
            cmake_args += ["-DCMAKE_BUILD_TYPE=" + cfg]
            build_args += ["--", "-j", "6"]

        env = os.environ.copy()
        env["CXXFLAGS"] = '{} -DVERSION_INFO=\\"{}\\"'.format(
            env.get("CXXFLAGS", ""), self.distribution.get_version()
        )
        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)
        subprocess.check_call(
            ["cmake", ext.sourcedir] + cmake_args, cwd=self.build_temp, env=env
        )
        subprocess.check_call(
            ["cmake", "--build", "."] + build_args, cwd=self.build_temp
        )


setup(
    name=name,
    version="1.0.0",
    author="David L. Adei",
    author_email="lokingdav@gmail.com",
    description="Python Binding for Control Plane Extension Library in C++",
    python_requires=">=3.7",
    install_requires=["wheel"],
    long_description=open("bindings/python/README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/lokingdav/libjodi",
    ext_modules=[CMakeExtension(name, ".")],
    cmdclass=dict(build_ext=CMakeBuild),
    zip_safe=False,
)