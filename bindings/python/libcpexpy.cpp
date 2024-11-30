#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "../../include/libcpex.hpp"

namespace py = pybind11;

using namespace libcpex;

PYBIND11_MODULE(libcpexpy, m)
{
   // bindings here
   
    #ifdef VERSION_INFO
        m.attr("__version__") = VERSION_INFO;
    #else
        m.attr("__version__") = "dev";
    #endif
}
