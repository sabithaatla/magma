/**
 * Copyright 2020 The Magma Authors.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "lte/gateway/c/core/oai/tasks/amf/amf_app_defs.h"
#include "lte/gateway/c/core/oai/tasks/amf/amf_app_state_converter.h"
#include "lte/gateway/c/core/oai/include/map.h"
using ::testing::Test;

namespace magma5g {
TEST(test_guti_to_string, test_guti_to_string) {
  guti_m5_t guti1, guti2;
  guti1.guamfi.plmn.mcc_digit1 = 2;
  guti1.guamfi.plmn.mcc_digit2 = 2;
  guti1.guamfi.plmn.mcc_digit3 = 2;
  guti1.guamfi.plmn.mnc_digit1 = 4;
  guti1.guamfi.plmn.mnc_digit2 = 5;
  guti1.guamfi.plmn.mnc_digit3 = 6;
  guti1.guamfi.amf_regionid    = 1;
  guti1.guamfi.amf_set_id      = 1;
  guti1.guamfi.amf_pointer     = 0;
  guti1.m_tmsi                 = 0X212e5025;

  std::string guti1_str =
      AmfNasStateConverter::amf_app_convert_guti_m5_to_string(guti1);

  AmfNasStateConverter::amf_app_convert_string_to_guti_m5(guti1_str, &guti2);

  EXPECT_EQ(guti1.guamfi.plmn.mcc_digit1, guti2.guamfi.plmn.mcc_digit1);
  EXPECT_EQ(guti1.guamfi.plmn.mcc_digit2, guti2.guamfi.plmn.mcc_digit2);
  EXPECT_EQ(guti1.guamfi.plmn.mcc_digit3, guti2.guamfi.plmn.mcc_digit3);
  EXPECT_EQ(guti1.guamfi.plmn.mnc_digit1, guti2.guamfi.plmn.mnc_digit1);
  EXPECT_EQ(guti1.guamfi.plmn.mnc_digit2, guti2.guamfi.plmn.mnc_digit2);
  EXPECT_EQ(guti1.guamfi.plmn.mnc_digit3, guti2.guamfi.plmn.mnc_digit3);
  EXPECT_EQ(guti1.guamfi.amf_regionid, guti2.guamfi.amf_regionid);
  EXPECT_EQ(guti1.guamfi.amf_set_id, guti2.guamfi.amf_set_id);
  EXPECT_EQ(guti1.guamfi.amf_pointer, guti2.guamfi.amf_pointer);
  EXPECT_EQ(guti1.m_tmsi, guti2.m_tmsi);
}

TEST(test_state_to_proto, test_state_to_proto) {
  // Guti setup
  guti_m5_t guti1;
  memset(&guti1, 0, sizeof(guti1));

  guti1.guamfi.plmn.mcc_digit1 = 2;
  guti1.guamfi.plmn.mcc_digit2 = 2;
  guti1.guamfi.plmn.mcc_digit3 = 2;
  guti1.guamfi.plmn.mnc_digit1 = 4;
  guti1.guamfi.plmn.mnc_digit2 = 5;
  guti1.guamfi.plmn.mnc_digit3 = 6;
  guti1.guamfi.amf_regionid    = 1;
  guti1.guamfi.amf_set_id      = 1;
  guti1.guamfi.amf_pointer     = 0;
  guti1.m_tmsi                 = 556683301;

  amf_app_desc_t amf_app_desc1 = {}, amf_app_desc2 = {};
  magma::lte::oai::MmeNasState state_proto = magma::lte::oai::MmeNasState();
  uint64_t data                            = 0;

  amf_app_desc1.amf_app_ue_ngap_id_generator = 0x05;
  amf_app_desc1.amf_ue_contexts.imsi_amf_ue_id_htbl.insert(1, 10);
  amf_app_desc1.amf_ue_contexts.tun11_ue_context_htbl.insert(2, 20);
  amf_app_desc1.amf_ue_contexts.gnb_ue_ngap_id_ue_context_htbl.insert(3, 30);
  amf_app_desc1.amf_ue_contexts.guti_ue_context_htbl.insert(guti1, 40);

  AmfNasStateConverter::state_to_proto(&amf_app_desc1, &state_proto);

  AmfNasStateConverter::proto_to_state(state_proto, &amf_app_desc2);

  EXPECT_EQ(
      amf_app_desc1.amf_app_ue_ngap_id_generator,
      amf_app_desc2.amf_app_ue_ngap_id_generator);

  EXPECT_EQ(
      amf_app_desc2.amf_ue_contexts.imsi_amf_ue_id_htbl.get(1, &data),
      magma::MAP_OK);
  EXPECT_EQ(data, 10);
  data = 0;

  EXPECT_EQ(
      amf_app_desc2.amf_ue_contexts.tun11_ue_context_htbl.get(2, &data),
      magma::MAP_OK);
  EXPECT_EQ(data, 20);
  data = 0;

  EXPECT_EQ(
      amf_app_desc2.amf_ue_contexts.gnb_ue_ngap_id_ue_context_htbl.get(
          3, &data),
      magma::MAP_OK);
  EXPECT_EQ(data, 30);
  data = 0;

  EXPECT_EQ(
      amf_app_desc2.amf_ue_contexts.guti_ue_context_htbl.get(guti1, &data),
      magma::MAP_OK);
  EXPECT_EQ(data, 40);
}

TEST(test_stateless, test_smf_context_to_proto) {
  smf_context_t smf_context1 = {}, smf_context2 = {};
  magma::lte::oai::SmfContext state_smf_proto = magma::lte::oai::SmfContext();
  smf_context1.pdu_session_state              = ACTIVE;
  smf_context1.pdu_session_version            = 0;
  smf_context1.n_active_pdus                  = 0;
  smf_context1.is_emergency                   = false;

  // selected ambr
  smf_context1.selected_ambr.dl_ambr_unit    = KBPS;
  smf_context1.selected_ambr.dl_session_ambr = 10000;
  smf_context1.selected_ambr.ul_ambr_unit    = KBPS;
  smf_context1.selected_ambr.ul_session_ambr = 1000;

  // gtp_tunnel_id
  // gnb
  smf_context1.gtp_tunnel_id.gnb_gtp_teid            = 1;
  smf_context1.gtp_tunnel_id.gnb_gtp_teid_ip_addr[0] = 0xc0;
  smf_context1.gtp_tunnel_id.gnb_gtp_teid_ip_addr[1] = 0xa8;
  smf_context1.gtp_tunnel_id.gnb_gtp_teid_ip_addr[2] = 0x3c;
  smf_context1.gtp_tunnel_id.gnb_gtp_teid_ip_addr[3] = 0x96;
  // upf
  smf_context1.gtp_tunnel_id.upf_gtp_teid[0] = 0x0;
  smf_context1.gtp_tunnel_id.upf_gtp_teid[1] = 0x0;
  smf_context1.gtp_tunnel_id.upf_gtp_teid[2] = 0x0;
  smf_context1.gtp_tunnel_id.upf_gtp_teid[3] = 0x1;

  smf_context1.gtp_tunnel_id.upf_gtp_teid_ip_addr[0] = 0xc0;
  smf_context1.gtp_tunnel_id.upf_gtp_teid_ip_addr[1] = 0xa8;
  smf_context1.gtp_tunnel_id.upf_gtp_teid_ip_addr[2] = 0x3c;
  smf_context1.gtp_tunnel_id.upf_gtp_teid_ip_addr[3] = 0xad;

  // pdu address
  smf_context1.pdu_address.pdn_type            = IPv4;
  smf_context1.pdu_address.ipv4_address.s_addr = 0x0441a8c0;

  // apn_ambr
  smf_context1.apn_ambr.br_dl   = 10000;
  smf_context1.apn_ambr.br_ul   = 1000;
  smf_context1.apn_ambr.br_unit = KBPS;

  // smf_proc_data
  smf_context1.smf_proc_data.pdu_session_id   = 1;
  smf_context1.smf_proc_data.pdu_session_type = IPv4;
  smf_context1.smf_proc_data.pti              = 0x01;
  smf_context1.smf_proc_data.ssc_mode         = SSC_MODE_3;
  smf_context1.smf_proc_data.max_uplink       = 0xFF;
  smf_context1.smf_proc_data.max_downlink     = 0xFF;

  smf_context1.retransmission_count = 1;

  // PCO
  smf_context1.pco.num_protocol_or_container_id = 2;
  smf_context1.pco.protocol_or_container_ids[0].id =
      PCO_CI_P_CSCF_IPV6_ADDRESS_REQUEST;
  bstring test_string1 = bfromcstr("teststring");
  smf_context1.pco.protocol_or_container_ids[0].contents = test_string1;
  smf_context1.pco.protocol_or_container_ids[0].length = blength(test_string1);
  smf_context1.pco.protocol_or_container_ids[1].id =
      PCO_CI_DSMIPV6_IPV4_HOME_AGENT_ADDRESS;
  bstring test_string2 = bfromcstr("longer.test.string");
  smf_context1.pco.protocol_or_container_ids[1].contents = test_string2;
  smf_context1.pco.protocol_or_container_ids[1].length = blength(test_string2);

  // dnn
  smf_context1.dnn = "internet";

  // nssai
  smf_context1.requested_nssai.sd[0] = 0x03;
  smf_context1.requested_nssai.sd[1] = 0x06;
  smf_context1.requested_nssai.sd[2] = 0x09;
  smf_context1.requested_nssai.sst   = 1;

  // Qos
  smf_context1.subscribebed_qos_profile.qos_flow_req_item.qos_flow_identifier =
      9;
  smf_context1.subscribebed_qos_profile.qos_flow_req_item
      .qos_flow_level_qos_param.qos_characteristic.non_dynamic_5QI_desc.fiveQI =
      9;
  smf_context1.subscribebed_qos_profile.qos_flow_req_item
      .qos_flow_level_qos_param.alloc_reten_priority.priority_level = 1;
  smf_context1.subscribebed_qos_profile.qos_flow_req_item
      .qos_flow_level_qos_param.alloc_reten_priority.pre_emption_cap =
      SHALL_NOT_TRIGGER_PRE_EMPTION;
  smf_context1.subscribebed_qos_profile.qos_flow_req_item
      .qos_flow_level_qos_param.alloc_reten_priority.pre_emption_vul =
      NOT_PREEMPTABLE;

  AmfNasStateConverter::smf_context_to_proto(&smf_context1, &state_smf_proto);
  AmfNasStateConverter::proto_to_smf_context(state_smf_proto, &smf_context2);

  EXPECT_EQ(smf_context1.pdu_session_state, smf_context2.pdu_session_state);
  EXPECT_EQ(smf_context1.pdu_session_version, smf_context2.pdu_session_version);
  EXPECT_EQ(smf_context1.n_active_pdus, smf_context2.n_active_pdus);
  EXPECT_EQ(smf_context1.is_emergency, smf_context2.is_emergency);

  EXPECT_EQ(
      smf_context1.selected_ambr.dl_ambr_unit,
      smf_context2.selected_ambr.dl_ambr_unit);
  EXPECT_EQ(
      smf_context1.selected_ambr.dl_session_ambr,
      smf_context2.selected_ambr.dl_session_ambr);
  EXPECT_EQ(
      smf_context1.selected_ambr.ul_ambr_unit,
      smf_context2.selected_ambr.ul_ambr_unit);
  EXPECT_EQ(
      smf_context1.selected_ambr.ul_session_ambr,
      smf_context2.selected_ambr.ul_session_ambr);

  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.gnb_gtp_teid,
      smf_context2.gtp_tunnel_id.gnb_gtp_teid);
  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.gnb_gtp_teid_ip_addr[0],
      smf_context2.gtp_tunnel_id.gnb_gtp_teid_ip_addr[0]);
  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.gnb_gtp_teid_ip_addr[1],
      smf_context2.gtp_tunnel_id.gnb_gtp_teid_ip_addr[1]);
  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.gnb_gtp_teid_ip_addr[2],
      smf_context2.gtp_tunnel_id.gnb_gtp_teid_ip_addr[2]);
  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.gnb_gtp_teid_ip_addr[3],
      smf_context2.gtp_tunnel_id.gnb_gtp_teid_ip_addr[3]);

  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.upf_gtp_teid[0],
      smf_context2.gtp_tunnel_id.upf_gtp_teid[0]);
  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.upf_gtp_teid[1],
      smf_context2.gtp_tunnel_id.upf_gtp_teid[1]);
  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.upf_gtp_teid[2],
      smf_context2.gtp_tunnel_id.upf_gtp_teid[2]);
  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.upf_gtp_teid[3],
      smf_context2.gtp_tunnel_id.upf_gtp_teid[3]);

  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.upf_gtp_teid_ip_addr[0],
      smf_context2.gtp_tunnel_id.upf_gtp_teid_ip_addr[0]);
  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.upf_gtp_teid_ip_addr[1],
      smf_context2.gtp_tunnel_id.upf_gtp_teid_ip_addr[1]);
  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.upf_gtp_teid_ip_addr[2],
      smf_context2.gtp_tunnel_id.upf_gtp_teid_ip_addr[2]);
  EXPECT_EQ(
      smf_context1.gtp_tunnel_id.upf_gtp_teid_ip_addr[3],
      smf_context2.gtp_tunnel_id.upf_gtp_teid_ip_addr[3]);

  EXPECT_EQ(
      smf_context1.pdu_address.pdn_type, smf_context2.pdu_address.pdn_type);
  EXPECT_EQ(
      smf_context1.pdu_address.ipv4_address.s_addr,
      smf_context2.pdu_address.ipv4_address.s_addr);

  EXPECT_EQ(smf_context1.apn_ambr.br_dl, smf_context2.apn_ambr.br_dl);
  EXPECT_EQ(smf_context1.apn_ambr.br_ul, smf_context1.apn_ambr.br_ul);
  EXPECT_EQ(smf_context1.apn_ambr.br_unit, smf_context1.apn_ambr.br_unit);

  EXPECT_EQ(
      smf_context1.smf_proc_data.pdu_session_id,
      smf_context2.smf_proc_data.pdu_session_id);
  EXPECT_EQ(
      smf_context1.smf_proc_data.pdu_session_type,
      smf_context2.smf_proc_data.pdu_session_type);
  EXPECT_EQ(smf_context1.smf_proc_data.pti, smf_context2.smf_proc_data.pti);
  EXPECT_EQ(
      smf_context1.smf_proc_data.ssc_mode, smf_context2.smf_proc_data.ssc_mode);
  EXPECT_EQ(
      smf_context1.smf_proc_data.max_uplink,
      smf_context2.smf_proc_data.max_uplink);
  EXPECT_EQ(
      smf_context1.smf_proc_data.max_downlink,
      smf_context2.smf_proc_data.max_downlink);

  EXPECT_EQ(
      smf_context1.retransmission_count, smf_context2.retransmission_count);

  EXPECT_EQ(
      smf_context1.pco.num_protocol_or_container_id,
      smf_context2.pco.num_protocol_or_container_id);
  EXPECT_EQ(
      smf_context1.pco.protocol_or_container_ids[0].id,
      smf_context2.pco.protocol_or_container_ids[0].id);

  std::string contents;
  BSTRING_TO_STRING(
      smf_context2.pco.protocol_or_container_ids[0].contents, &contents);
  EXPECT_EQ(contents, "teststring");
  EXPECT_EQ(
      smf_context1.pco.protocol_or_container_ids[0].length,
      smf_context2.pco.protocol_or_container_ids[0].length);

  contents = {};

  EXPECT_EQ(
      smf_context1.pco.protocol_or_container_ids[1].id,
      smf_context2.pco.protocol_or_container_ids[1].id);
  BSTRING_TO_STRING(
      smf_context2.pco.protocol_or_container_ids[1].contents, &contents);
  EXPECT_EQ(contents, "longer.test.string");
  EXPECT_EQ(
      smf_context1.pco.protocol_or_container_ids[1].length,
      smf_context2.pco.protocol_or_container_ids[1].length);

  EXPECT_EQ(smf_context1.dnn, smf_context2.dnn);

  EXPECT_EQ(
      smf_context1.requested_nssai.sd[0], smf_context2.requested_nssai.sd[0]);
  EXPECT_EQ(
      smf_context1.requested_nssai.sd[1], smf_context2.requested_nssai.sd[1]);
  EXPECT_EQ(
      smf_context1.requested_nssai.sd[2], smf_context2.requested_nssai.sd[2]);
  EXPECT_EQ(smf_context1.requested_nssai.sst, smf_context2.requested_nssai.sst);

  EXPECT_EQ(
      smf_context1.subscribebed_qos_profile.qos_flow_req_item
          .qos_flow_identifier,
      smf_context2.subscribebed_qos_profile.qos_flow_req_item
          .qos_flow_identifier);
  EXPECT_EQ(
      smf_context1.subscribebed_qos_profile.qos_flow_req_item
          .qos_flow_level_qos_param.qos_characteristic.non_dynamic_5QI_desc
          .fiveQI,
      smf_context2.subscribebed_qos_profile.qos_flow_req_item
          .qos_flow_level_qos_param.qos_characteristic.non_dynamic_5QI_desc
          .fiveQI);

  EXPECT_EQ(
      smf_context1.subscribebed_qos_profile.qos_flow_req_item
          .qos_flow_level_qos_param.alloc_reten_priority.priority_level,
      smf_context2.subscribebed_qos_profile.qos_flow_req_item
          .qos_flow_level_qos_param.alloc_reten_priority.priority_level);

  EXPECT_EQ(
      smf_context1.subscribebed_qos_profile.qos_flow_req_item
          .qos_flow_level_qos_param.alloc_reten_priority.pre_emption_cap,
      smf_context2.subscribebed_qos_profile.qos_flow_req_item
          .qos_flow_level_qos_param.alloc_reten_priority.pre_emption_cap);

  EXPECT_EQ(
      smf_context1.subscribebed_qos_profile.qos_flow_req_item
          .qos_flow_level_qos_param.alloc_reten_priority.pre_emption_vul,
      smf_context2.subscribebed_qos_profile.qos_flow_req_item
          .qos_flow_level_qos_param.alloc_reten_priority.pre_emption_vul);

  bdestroy(smf_context2.pco.protocol_or_container_ids[0].contents);
  bdestroy(smf_context2.pco.protocol_or_container_ids[1].contents);
  bdestroy(test_string1);
  bdestroy(test_string2);
}
}  // namespace magma5g
