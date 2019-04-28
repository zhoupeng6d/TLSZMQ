# - Try to find ZMQ
# Once done this will define
# ZMQ_FOUND - System has ZMQ
# ZMQ_INCLUDE_DIRS - The ZMQ include directories
# ZMQ_LIBRARIES - The libraries needed to use ZMQ
# ZMQ_DEFINITIONS - Compiler switches required for using ZMQ

find_path(ZEROMQ_INCLUDE_DIR zmq.h)
find_library(ZEROMQ_LIBRARY NAMES zmq)

set(ZEROMQ_LIBRARIES ${ZEROMQ_LIBRARY})
set(ZEROMQ_INCLUDE_DIR ${ZEROMQ_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set ZMQ_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(ZEROMQ DEFAULT_MSG ZEROMQ_LIBRARY ZEROMQ_INCLUDE_DIR)
