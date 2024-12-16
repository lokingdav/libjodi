#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "../../src/libcpex/libcpex.hpp"

namespace py = pybind11;

using namespace libcpex;

Bytes PyBytesToBytes(const py::bytes& data) {
    std::string datastr(data);
    return Bytes(datastr.begin(), datastr.end());
}

py::bytes BytesToPyBytes(const Bytes& data) {
    return py::bytes((char*)data.data(), data.size());
}

PYBIND11_MODULE(pylibcpex, module)
{
    py::class_<Utils>(module, "Utils")
        .def_static("hash160", [](const py::bytes& data) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Utils::Sha160(PyBytesToBytes(data)));
        })
        .def_static("hash256", [](const py::bytes& data) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Utils::Sha256(PyBytesToBytes(data)));
        })
        .def_static("to_base64", [](const py::bytes& data) {
            py::gil_scoped_release release;
            return Utils::EncodeBase64(PyBytesToBytes(data));
        })
        .def_static("from_base64", [](const py::str& data) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Utils::DecodeBase64(data));
        })
        .def_static("xor", [](const py::bytes& x, const py::bytes& y) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Utils::Xor(PyBytesToBytes(x), PyBytesToBytes(y)));
        })
        .def_static("random_bytes", [](const py::size_t size) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Utils::RandomBytes(size));
        });

    py::class_<Ciphering>(module, "Ciphering")
        .def_static("keygen", []() {
            py::gil_scoped_release release;
            return BytesToPyBytes(Ciphering::Keygen());
        })
        .def_static("enc", [](const py::bytes& key, const py::bytes& plaintext) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Ciphering::Encrypt(PyBytesToBytes(key), PyBytesToBytes(plaintext)));
        })
        .def_static("dec", [](const py::bytes& key, const py::bytes& ciphertext) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Ciphering::Encrypt(PyBytesToBytes(key), PyBytesToBytes(ciphertext)));
        });

    py::class_<OPRF>(module, "Oprf")
        .def_static("keygen", []() {
            py::gil_scoped_release release;
            OPRF_Keypair keypair = OPRF::Keygen();
            return py::make_tuple(
                BytesToPyBytes(keypair.sk), 
                BytesToPyBytes(keypair.pk)
            );
        })
        .def_static("mask", [](const py::str& msg) {
            py::gil_scoped_release release;
            string msg_str(msg);
            OPRF_Blinded result = OPRF::Blind(&msg_str);
            return py::make_tuple(
                BytesToPyBytes(result.mask), 
                BytesToPyBytes(result.sk)
            );
        })
        .def_static("evaluate", [](const py::bytes& sk, const py::bytes& pk, const py::bytes& x) {
            py::gil_scoped_release release;
            OPRF_Keypair keypair(PyBytesToBytes(sk), PyBytesToBytes(pk));
            OPRF_BlindedEval eval = OPRF::Evaluate(keypair, PyBytesToBytes(x));
            return py::make_tuple(
                BytesToPyBytes(eval.fx), 
                BytesToPyBytes(eval.pk)
            );
        })
        .def_static("unmask", [](const py::bytes& fx, const py::bytes& pk, const py::bytes& sk) {
            py::gil_scoped_release release;
            OPRF_BlindedEval eval(PyBytesToBytes(fx), PyBytesToBytes(pk));
            Bytes seck = PyBytesToBytes(sk);
            return BytesToPyBytes(OPRF::Unblind(eval, seck));
        });

    py::class_<KeyRotation>(module, "KeyRotation")
        .def("start_rotation", [](const py::size_t& size, const py::size_t& interval) {
            py::gil_scoped_release release;
            KeyRotation::GetInstance()->StartRotation(size, interval);
        })
        .def("stop_rotation", []() {
            py::gil_scoped_release release;
            KeyRotation::GetInstance()->StopRotation();
        })
        .def("is_expired_within", [](const py::size_t& index, const py::size_t& tmax) {
            py::gil_scoped_release release;
            return KeyRotation::GetInstance()->IsExpiredWithin(index, tmax);
        })
        .def("get_list_size", []() {
            py::gil_scoped_release release;
            return KeyRotation::GetInstance()->GetListSize();
        })
        .def("get_recently_expired_key", [](const py::size_t& index) {
            py::gil_scoped_release release;
            OPRF_Keypair kp = KeyRotation::GetInstance()->GetRecentlyExpiredKey();
            return py::make_tuple(
                BytesToPyBytes(kp.sk), 
                BytesToPyBytes(kp.pk)
            );
        })
        .def("get_key", [](const py::size_t& index) {
            py::gil_scoped_release release;
            OPRF_Keypair kp = KeyRotation::GetInstance()->GetKey(index);
            return py::make_tuple(
                BytesToPyBytes(kp.sk), 
                BytesToPyBytes(kp.pk)
            );
        })
        .def_static("get_instance", []() {
            py::gil_scoped_release release;
            return KeyRotation::GetInstance();
        });

    #ifdef LIBCPEX_VERSION
        module.attr("__version__") = LIBCPEX_VERSION;
    #else
        module.attr("__version__") = "dev";
    #endif
}
