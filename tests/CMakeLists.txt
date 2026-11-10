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

add_executable(tcp_close tcp_close.c test_utils.c ../zdtun.c ../utils.c)
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
  no_rst_reply_to_client_rst
  no_rst_reply_to_client_rst_after_server_eof
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
  queued_upload_sent_after_server_eof
  upload_delivered_after_server_half_close
  fin_propagated_after_server_half_close
  fin_terminates_when_server_closed
  fin_payload_delivered_after_server_eof
  fin_payload_retransmission_after_close
  fin_payload_retransmission_seq_wrap
  fin_payload_retransmission_while_queued
  non_fin_dup_acked_at_fin_payload_seq
  old_segment_dup_acked
  future_segment_dup_acked
  old_pure_ack_not_replied
  queued_upload_not_acked_at_server_eof
  partially_sent_upload_delivered_after_server_eof
  fin_acked_after_server_eof_with_queued_upload
  data_queued_after_server_eof_with_queued_upload
  rst_on_send_error_after_server_eof
  rst_after_upload_to_closed_server
  rst_after_fin_payload_to_closed_server
  rst_after_fin_following_upload_to_closed_server
  rst_on_idle_timeout_after_server_eof
  window_update_applied_by_fin
  window_update_applied_by_fin_retransmission
  server_eof_not_polled_after_fin_retransmission
)

foreach(TEST_NAME ${TCP_CLOSE_TESTS})
  add_test(NAME tcp_close_${TEST_NAME} COMMAND tcp_close ${TEST_NAME})
endforeach()

add_executable(stack stack.c test_utils.c ../zdtun.c ../utils.c)
target_include_directories(stack PRIVATE ..)
target_link_options(stack PRIVATE -Wl,--wrap=connect,--wrap=socket)
add_dependencies(run_tests stack)

set(STACK_TESTS
  large_mss_clamped_to_mtu
  mss_clamped_to_configured_mtu
  small_mss_honored
  zero_mss_ignored
  short_tcp_data_offset_rejected
  short_ipv4_ihl_rejected
  syn_short_data_offset_not_forwarded
  rst_delivered_on_close
  failed_rst_closes_once
  failed_rst_on_destroy_closes_once
  connect_error_rst_acks_syn
  unforwarded_conn_close_sends_no_rst
  unforwarded_conn_destroy_sends_no_rst
  tcp_socket_error_closes_conn
  icmp_socket_error_closes_conn
  zero_window_ack_keeps_connection
  window_filled_by_in_flight_keeps_connection
  window_shrink_not_overrun
  zero_window_syn_keeps_connection
  zero_window_syn_connect_in_progress
  stale_read_event_with_zero_window
  zero_window_upload_delivered
  zero_window_syn_socks5_handshake
  socks5_server_close_during_handshake
  large_window_scale_clamped
  syn_ack_window_not_scaled
  window_scale_not_sent_unsolicited
  server_data_before_connect_handled
  server_eof_before_connect_handled
  server_reset_before_connect_handled
  server_data_queued_until_handshake_ack
  stale_read_event_before_handshake_ack
  retransmitted_byte_delivered_once
  retransmitted_byte_with_fin_delivered_once
  retransmitted_byte_delivered_once_after_server_eof
  ipv6_client_tcp_dnat_to_ipv4
  ipv6_client_udp_dnat_to_ipv4
  ipv6_udp_zero_checksum_not_sent
  ipv6_udp_to_scoped_addr_dropped
  ipv6_client_ipv4_socks5_proxy
)

foreach(TEST_NAME ${STACK_TESTS})
  add_test(NAME stack_${TEST_NAME} COMMAND stack ${TEST_NAME})
endforeach()
