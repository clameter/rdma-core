include_directories("linux")
include_directories(${NL_INCLUDE_DIRS})

rdma_executable(ib2roce
  ib2roce.c
  fifo.c
  hash.c
  errno.c
  ring.c
  sched.c
  channel.c
  logging.c
  locking.c
  buffers.c
  multicast.c
  unicast.c
  interfaces.c
  beacon.c
  cli.c
  endpoint.c
  pgm.c
)
target_link_libraries(ib2roce LINK_PRIVATE
  ibverbs
  ibumad
  rdmacm
  ${NL_LIBRARIES}
  ${SYSTEMD_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${CMAKE_DL_LIBS}
  numa
  )

rdma_executable(bcom
  bcom.c
)

add_link_options("--export-dynamic")

rdma_man_pages(
  man/ib2roce.1
  man/ib2roce.7
  )

rdma_subst_install(FILES "ib2roce.service.in"
  DESTINATION "${CMAKE_INSTALL_SYSTEMD_SERVICEDIR}"
  RENAME ib2roce.service
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)


