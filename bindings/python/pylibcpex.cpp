#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "../../src/libcpex/libcpex.hpp"

namespace py = pybind11;
using namespace libcpex;

// Convert py::bytes -> std::vector<uint8_t>
Bytes PyBytesToBytes(const py::bytes& data) {
    // This constructor internally calls Python APIs to get the buffer,
    // so the GIL must be held here.
    std::string datastr(data);
    return Bytes(datastr.begin(), datastr.end());
}

// Convert std::vector<uint8_t> -> py::bytes
py::bytes BytesToPyBytes(const Bytes& data) {
    // Creating py::bytes(...) touches the Python allocator/objects,
    // so the GIL must be held as well.
    return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
}

PYBIND11_MODULE(pylibcpex, module)
{
    InitMCL();

    //
    // Utils
    //
    py::class_<Utils>(module, "Utils")
        .def_static("hash160", [](const py::bytes& data) {
            // 1) Convert Python -> C++ with GIL held
            Bytes input = PyBytesToBytes(data);

            // 2) Release GIL for the pure C++ hashing
            {
                py::gil_scoped_release release;
                input = Utils::Sha160(input);
            }
            // GIL is re-acquired automatically after scope ends

            // 3) Return Python object under GIL
            return BytesToPyBytes(input);
        }, py::arg("data"))

        .def_static("hash256", [](const py::bytes& data) {
            Bytes input = PyBytesToBytes(data);
            {
                py::gil_scoped_release release;
                input = Utils::Sha256(input);
            }
            return BytesToPyBytes(input);
        }, py::arg("data"))

        .def_static("to_base64", [](const py::bytes& data) {
            // `EncodeBase64` returns a std::string (pure C++).
            // We do not need GIL for that part, but we do need GIL to parse `data`.
            Bytes input = PyBytesToBytes(data);

            std::string encoded;
            {
                py::gil_scoped_release release;
                encoded = Utils::EncodeBase64(input);
            }
            // Returning a C++ std::string to Python is safe after re-acquiring GIL;
            // pybind11 will convert it to py::str automatically.
            return encoded;
        }, py::arg("data"))

        .def_static("from_base64", [](const py::str& data) {
            // Converting py::str -> std::string requires GIL
            std::string base64_str(data);

            Bytes decoded;
            {
                py::gil_scoped_release release;
                decoded = Utils::DecodeBase64(base64_str);
            }
            return BytesToPyBytes(decoded);
        }, py::arg("data"))

        .def_static("xor", [](const py::bytes& x, const py::bytes& y) {
            Bytes bx = PyBytesToBytes(x);
            Bytes by = PyBytesToBytes(y);

            Bytes result;
            {
                py::gil_scoped_release release;
                result = Utils::Xor(bx, by);
            }
            return BytesToPyBytes(result);
        }, py::arg("x"), py::arg("y"))

        .def_static("random_bytes", [](py::size_t size) {
            // 'size' is just a numeric type, no Python-object calls needed for reading it.
            Bytes random_data;
            {
                py::gil_scoped_release release;
                random_data = Utils::RandomBytes(size);
            }
            return BytesToPyBytes(random_data);
        }, py::arg("size"));

    //
    // Ciphering
    //
    py::class_<Ciphering>(module, "Ciphering")
        .def_static("keygen", []() {
            Bytes key;
            {
                py::gil_scoped_release release;
                key = Ciphering::Keygen();
            }
            return BytesToPyBytes(key);
        })

        .def_static("enc", [](const py::bytes& key, const py::bytes& plaintext) {
            Bytes k = PyBytesToBytes(key);
            Bytes pt = PyBytesToBytes(plaintext);

            Bytes ct;
            {
                py::gil_scoped_release release;
                ct = Ciphering::Encrypt(k, pt);
            }
            return BytesToPyBytes(ct);
        }, py::arg("key"), py::arg("plaintext"))

        .def_static("dec", [](const py::bytes& key, const py::bytes& ciphertext) {
            Bytes k = PyBytesToBytes(key);
            Bytes ct = PyBytesToBytes(ciphertext);

            Bytes pt;
            {
                py::gil_scoped_release release;
                pt = Ciphering::Decrypt(k, ct);
            }
            return BytesToPyBytes(pt);
        }, py::arg("key"), py::arg("ciphertext"));

    //
    // OPRF
    //
    py::class_<OPRF>(module, "Oprf")
        .def_static("keygen", []() {
            OPRF_Keypair kp;
            {
                py::gil_scoped_release release;
                kp = OPRF::Keygen();
            }
            return py::make_tuple(BytesToPyBytes(kp.sk),
                                  BytesToPyBytes(kp.pk));
        })

        .def_static("blind", [](const py::str& msg) {
            // Convert py::str -> std::string under GIL
            std::string msg_str(msg);

            OPRF_Blinded blinded;
            {
                py::gil_scoped_release release;
                blinded = OPRF::Blind(msg_str);
            }
            return py::make_tuple(BytesToPyBytes(blinded.x),
                                  BytesToPyBytes(blinded.r));
        }, py::arg("msg"))

        .def_static("evaluate", [](const py::bytes& privk,
                                   const py::bytes& publk,
                                   const py::bytes& x) {
            Bytes sk = PyBytesToBytes(privk);
            Bytes pk = PyBytesToBytes(publk);
            Bytes in_x = PyBytesToBytes(x);

            OPRF_BlindedEval eval;
            {
                py::gil_scoped_release release;
                OPRF_Keypair keypair(sk, pk);
                eval = OPRF::Evaluate(keypair, in_x);
            }
            return py::make_tuple(BytesToPyBytes(eval.fx),
                                  BytesToPyBytes(eval.vk));
        }, py::arg("privk"), py::arg("publk"), py::arg("x"))

        .def_static("unblind", [](const py::bytes& fx,
                                  const py::bytes& vk,
                                  const py::bytes& r) {
            Bytes fx_bytes = PyBytesToBytes(fx);
            Bytes vk_bytes = PyBytesToBytes(vk);
            Bytes r_bytes = PyBytesToBytes(r);

            Bytes unblinded;
            {
                py::gil_scoped_release release;
                OPRF_BlindedEval eval(fx_bytes, vk_bytes);
                unblinded = OPRF::Unblind(eval, r_bytes);
            }
            return BytesToPyBytes(unblinded);
        }, py::arg("fx"), py::arg("vk"), py::arg("r"));

    //
    // KeyRotation
    //
    py::class_<KeyRotation, std::shared_ptr<KeyRotation>>(module, "KeyRotation")
        .def("start_rotation", [](KeyRotation &self, int size, int interval) {
            {
                py::gil_scoped_release release;
                self.StartRotation(size, interval);
            }
        }, py::arg("size"), py::arg("interval"))

        .def("stop_rotation", [](KeyRotation &self) {
            {
                py::gil_scoped_release release;
                self.StopRotation();
            }
        })

        .def("is_expired_within", [](KeyRotation &self, int index, int tmax) {
            bool result;
            {
                py::gil_scoped_release release;
                result = self.IsExpiredWithin(index, tmax);
            }
            return result;
        }, py::arg("index"), py::arg("tmax"))

        .def("get_list_size", [](KeyRotation &self) {
            int size;
            {
                py::gil_scoped_release release;
                size = self.GetListSize();
            }
            return size;
        })

        .def("get_recently_expired_key", [](KeyRotation &self) {
            OPRF_Keypair kp;
            {
                py::gil_scoped_release release;
                kp = self.GetRecentlyExpiredKey();
            }
            return py::make_tuple(BytesToPyBytes(kp.sk),
                                  BytesToPyBytes(kp.pk));
        })

        .def("get_key", [](KeyRotation &self, int index) {
            OPRF_Keypair kp;
            {
                py::gil_scoped_release release;
                kp = self.GetKey(index);
            }
            return py::make_tuple(BytesToPyBytes(kp.sk),
                                  BytesToPyBytes(kp.pk));
        }, py::arg("index"))

        .def_static("get_instance", []() {
            py::gil_scoped_release release;
            return KeyRotation::GetInstance();
        });

    /**
     * VOPRF
     */
    py::class_<OPRF>(module, "Oprf")
        .def_static("keygen", []() {
            PrivateKey sk;
            PublicKey pk;
            {
                py::gil_scoped_release release;
                sk = PrivateKey::Keygen();
                pk = sk.GetPublicKey();
            }
            return py::make_tuple(BytesToPyBytes(sk.ToBytes()),
                                  BytesToPyBytes(pk.ToBytes()));
        })
        .def_static("blind", [](const py::str& msg) {
            std::string msg_str(msg);

            VOPRF_Blinded blinded;
            {
                py::gil_scoped_release release;
                blinded = VOPRF::Blind(msg_str);
            }
            return py::make_tuple(BytesToPyBytes(blinded.x.ToBytes()),
                                  BytesToPyBytes(blinded.r.ToBytes()));
        }, py::arg("msg"))

        .def_static("evaluate", [](const py::bytes& k, const py::bytes& x) {
            PrivateKey sk = PrivateKey::FromBytes(PyBytesToBytes(k));
            Point in_x = Point::FromBytes(PyBytesToBytes(x));

            Point fx;
            {
                py::gil_scoped_release release;
                fx = VOPRF::Evaluate(sk, in_x);
            }
            return BytesToPyBytes(fx.ToBytes());
        }, py::arg("sk"), py::arg("x"))

        .def_static("unblind", [](const py::bytes& fx, const py::bytes& r) {
            Point fx_bytes = Point::FromBytes(PyBytesToBytes(fx));
            PrivateKey r_bytes = PrivateKey::FromBytes(PyBytesToBytes(r));

            Point unblinded;
            {
                py::gil_scoped_release release;
                unblinded = VOPRF::Unblind(fx_bytes, r_bytes);
            }
            return BytesToPyBytes(unblinded.ToBytes());
        }, py::arg("fx"), py::arg("r"))

        .def_static("verify", [](const py::bytes& _pk, const py::bytes& x, const py::bytes& y) {
            PublicKey pk = PublicKey::FromBytes(PyBytesToBytes(_pk));
            Point in_x = Point::FromBytes(PyBytesToBytes(x));
            Point in_y = Point::FromBytes(PyBytesToBytes(y));

            bool valid;
            {
                py::gil_scoped_release release;
                valid = VOPRF::Verify(pk, in_x, in_y);
            }
            return valid;
        }, py::arg("pk"), py::arg("x"), py::arg("y"));

    // Module version
    #ifdef LIBCPEX_VERSION
        module.attr("__version__") = LIBCPEX_VERSION;
    #else
        module.attr("__version__") = "dev";
    #endif
}
