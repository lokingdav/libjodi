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
        }, py::arg("data"))

        .def_static("hash256", [](const py::bytes& data) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Utils::Sha256(PyBytesToBytes(data)));
        }, py::arg("data"))

        .def_static("to_base64", [](const py::bytes& data) {
            py::gil_scoped_release release;
            return Utils::EncodeBase64(PyBytesToBytes(data));
        }, py::arg("data"))

        .def_static("from_base64", [](const py::str& data) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Utils::DecodeBase64(data));
        }, py::arg("data"))

        .def_static("xor", [](const py::bytes& x, const py::bytes& y) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Utils::Xor(PyBytesToBytes(x), PyBytesToBytes(y)));
        }, py::arg("x"), py::arg("y"))

        .def_static("random_bytes", [](const py::size_t size) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Utils::RandomBytes(size));
        }, py::arg("size"));

    py::class_<Ciphering>(module, "Ciphering")
        .def_static("keygen", []() {
            py::gil_scoped_release release;
            return BytesToPyBytes(Ciphering::Keygen());
        })

        .def_static("enc", [](const py::bytes& key, const py::bytes& plaintext) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Ciphering::Encrypt(PyBytesToBytes(key), PyBytesToBytes(plaintext)));
        }, py::arg("key"), py::arg("plaintext"))

        .def_static("dec", [](const py::bytes& key, const py::bytes& ciphertext) {
            py::gil_scoped_release release;
            return BytesToPyBytes(Ciphering::Decrypt(PyBytesToBytes(key), PyBytesToBytes(ciphertext)));
        }, py::arg("key"), py::arg("ciphertext"));

    py::class_<OPRF>(module, "Oprf")
        .def_static("keygen", []() {
            py::gil_scoped_release release;
            OPRF_Keypair keypair = OPRF::Keygen();
            return py::make_tuple(
                BytesToPyBytes(keypair.sk), 
                BytesToPyBytes(keypair.pk)
            );
        })

        .def_static("blind", [](const py::str& msg) {
            py::gil_scoped_release release;
            string msg_str(msg);
            OPRF_Blinded result = OPRF::Blind(&msg_str);
            return py::make_tuple(
                BytesToPyBytes(result.x), 
                BytesToPyBytes(result.r)
            );
        }, py::arg("msg"))

        .def_static("evaluate", [](const py::bytes& privk, const py::bytes& publk, const py::bytes& x) {
            py::gil_scoped_release release;
            OPRF_Keypair keypair(PyBytesToBytes(privk), PyBytesToBytes(publk));
            OPRF_BlindedEval eval = OPRF::Evaluate(keypair, PyBytesToBytes(x));
            return py::make_tuple(
                BytesToPyBytes(eval.fx), 
                BytesToPyBytes(eval.vk)
            );
        }, py::arg("privk"), py::arg("publk"), py::arg("x"))

        .def_static("unblind", [](const py::bytes& fx, const py::bytes& vk, const py::bytes& r) {
            py::gil_scoped_release release;
            OPRF_BlindedEval eval(PyBytesToBytes(fx), PyBytesToBytes(vk));
            Bytes seck = PyBytesToBytes(r);
            return BytesToPyBytes(OPRF::Unblind(eval, seck));
        }, py::arg("fx"), py::arg("vk"), py::arg("r"));

    py::class_<KeyRotation, std::shared_ptr<KeyRotation>>(module, "KeyRotation")
        .def("start_rotation", [](KeyRotation &self, int size, int interval) {
            py::gil_scoped_release release;
            self.StartRotation(size, interval);
        }, py::arg("size"), py::arg("interval"))

        .def("stop_rotation", [](KeyRotation &self) {
            py::gil_scoped_release release;
            self.StopRotation();
        })

        .def("is_expired_within", [](KeyRotation &self, int index, int tmax) {
            py::gil_scoped_release release;
            return self.IsExpiredWithin(index, tmax);
        }, py::arg("index"), py::arg("tmax"))

        .def("get_list_size", [](KeyRotation &self) {
            py::gil_scoped_release release;
            return self.GetListSize();
        })

        .def("get_recently_expired_key", [](KeyRotation &self) {
            py::gil_scoped_release release;
            OPRF_Keypair kp = self.GetRecentlyExpiredKey();
            return py::make_tuple(
                BytesToPyBytes(kp.sk), 
                BytesToPyBytes(kp.pk)
            );
        })
        
        .def("get_key", [](KeyRotation &self, int index) {
            py::gil_scoped_release release;
            OPRF_Keypair kp = self.GetKey(index);
            return py::make_tuple(
                BytesToPyBytes(kp.sk), 
                BytesToPyBytes(kp.pk)
            );
        }, py::arg("index"))
        
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
