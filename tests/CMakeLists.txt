cmake_minimum_required(VERSION 3.18)
project(zdtun_tests C)

include(CTest)
include(TestBigEndian)

TEST_BIG_ENDIAN(IS_BIG_ENDIAN)

if(IS_BIG_ENDIAN)
  add_definitions(-D_BIG_ENDIAN)
else()
  add_definitions(-D_LITTLE_ENDIAN)
endif()

add_custom_target(run_tests COMMAND CTEST_OUTPUT_ON_FAILURE=1 ${CMAKE_CTEST_COMMAND})

add_executable(tcp_close tcp_close.c ../zdtun.c ../utils.c)
target_include_directories(tcp_close PRIVATE ..)
target_link_options(tcp_close PRIVATE -Wl,--wrap=send,--wrap=shutdown,--wrap=clock_gettime)
add_dependencies(run_tests tcp_close)

set(TCP_CLOSE_TESTS
  queued_data_delivered
  unpushed_queued_data_delivered
  fin_payload_delivered
  fin_propagated_to_server
  shutdown_deferred_while_queued
  fin_not_acked_while_queued
  partial_send_acks_written_bytes
  fin_acked_after_drain
  fin_payload_acked
  fin_acked_immediately_when_queue_empty
  fin_retransmission_while_queued
  fin_retransmission_after_close
  drain_progress_refreshes_idle_timeout
  window_update_applied_while_queued
  rst_after_fin_while_queued
  server_eof_keeps_connection_while_queued
  upload_delivered_after_server_eof
  fin_acked_after_server_eof
  connection_closed_after_server_eof_drain
  server_eof_not_polled_after_window_update
  server_fin_sent_once_while_queued
  send_error_after_server_eof_closes
  upload_sent_while_server_sending
  close_completed_while_server_sending
  drain_completed_with_server_eof
  queued_upload_not_sent_after_server_close
  fin_terminates_when_server_closed
  fin_payload_acked_when_server_closed
  queued_upload_acked_when_server_closes
  partially_sent_upload_acked_when_server_closes
  fin_acked_after_server_close_with_queued_upload
  data_acked_after_server_close_with_queued_upload
  window_update_applied_by_fin
  window_update_applied_by_fin_retransmission
  server_eof_not_polled_after_fin_retransmission
)

foreach(TEST_NAME ${TCP_CLOSE_TESTS})
  add_test(NAME tcp_close_${TEST_NAME} COMMAND tcp_close ${TEST_NAME})
endforeach()
