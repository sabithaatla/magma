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

TEST(test_amf_context_to_proto, test_amf_context_state_to_proto) {
#define AMF_CAUSE_SUCCESS 1
  amf_context_t amf_ctx1 = {}, amf_ctx2 = {};
  magma::lte::oai::EmmContext emm_context_proto = magma::lte::oai::EmmContext();

  amf_ctx1.imsi64             = 222456000000101;
  amf_ctx1.imsi.u.num.digit1  = 3;
  amf_ctx1.imsi.u.num.digit2  = 1;
  amf_ctx1.imsi.u.num.digit3  = 0;
  amf_ctx1.imsi.u.num.digit4  = 1;
  amf_ctx1.imsi.u.num.digit5  = 5;
  amf_ctx1.imsi.u.num.digit6  = 0;
  amf_ctx1.imsi.u.num.digit7  = 1;
  amf_ctx1.imsi.u.num.digit8  = 2;
  amf_ctx1.imsi.u.num.digit9  = 3;
  amf_ctx1.imsi.u.num.digit10 = 4;
  amf_ctx1.imsi.u.num.digit11 = 5;
  amf_ctx1.imsi.u.num.digit12 = 6;
  amf_ctx1.imsi.u.num.digit13 = 7;
  amf_ctx1.imsi.u.num.digit14 = 8;
  amf_ctx1.imsi.u.num.digit15 = 9;
  amf_ctx1.saved_imsi64       = 310150123456789;

  // imei
  amf_ctx1.imei.length       = 10;
  amf_ctx1.imei.u.num.tac2   = 2;
  amf_ctx1.imei.u.num.tac1   = 1;
  amf_ctx1.imei.u.num.tac3   = 3;
  amf_ctx1.imei.u.num.tac4   = 4;
  amf_ctx1.imei.u.num.tac5   = 5;
  amf_ctx1.imei.u.num.tac6   = 6;
  amf_ctx1.imei.u.num.tac7   = 7;
  amf_ctx1.imei.u.num.tac8   = 8;
  amf_ctx1.imei.u.num.snr1   = 1;
  amf_ctx1.imei.u.num.snr2   = 2;
  amf_ctx1.imei.u.num.snr3   = 3;
  amf_ctx1.imei.u.num.snr4   = 4;
  amf_ctx1.imei.u.num.snr5   = 5;
  amf_ctx1.imei.u.num.snr6   = 6;
  amf_ctx1.imei.u.num.parity = 1;
  amf_ctx1.imei.u.num.cdsd   = 8;
  for (int i = 0; i < IMEI_BCD8_SIZE; i++) {
    amf_ctx1.imei.u.value[i] = i;
  }

  // imeisv
  amf_ctx1.imeisv.length       = 10;
  amf_ctx1.imeisv.u.num.tac2   = 2;
  amf_ctx1.imeisv.u.num.tac1   = 1;
  amf_ctx1.imeisv.u.num.tac3   = 3;
  amf_ctx1.imeisv.u.num.tac4   = 4;
  amf_ctx1.imeisv.u.num.tac5   = 5;
  amf_ctx1.imeisv.u.num.tac6   = 6;
  amf_ctx1.imeisv.u.num.tac7   = 7;
  amf_ctx1.imeisv.u.num.tac8   = 8;
  amf_ctx1.imeisv.u.num.snr1   = 1;
  amf_ctx1.imeisv.u.num.snr2   = 2;
  amf_ctx1.imeisv.u.num.snr3   = 3;
  amf_ctx1.imeisv.u.num.snr4   = 4;
  amf_ctx1.imeisv.u.num.snr5   = 5;
  amf_ctx1.imeisv.u.num.snr6   = 6;
  amf_ctx1.imeisv.u.num.parity = 1;
  for (int i = 0; i < IMEISV_BCD8_SIZE; i++) {
    amf_ctx1.imeisv.u.value[i] = i;
  }
  amf_ctx1.amf_cause     = AMF_CAUSE_SUCCESS;
  amf_ctx1.amf_fsm_state = AMF_DEREGISTERED;

  amf_ctx1.m5gsregistrationtype = AMF_REGISTRATION_TYPE_INITIAL;
  amf_ctx1.member_present_mask |= AMF_CTXT_MEMBER_SECURITY;
  amf_ctx1.member_valid_mask |= AMF_CTXT_MEMBER_SECURITY;
  amf_ctx1.is_dynamic               = true;
  amf_ctx1.is_registered            = true;
  amf_ctx1.is_initial_identity_imsi = true;
  amf_ctx1.is_guti_based_registered = true;
  amf_ctx1.is_imsi_only_detach      = false;

  // originating_tai
  amf_ctx1.originating_tai.plmn.mcc_digit1 = 2;
  amf_ctx1.originating_tai.plmn.mcc_digit2 = 2;
  amf_ctx1.originating_tai.plmn.mcc_digit3 = 2;
  amf_ctx1.originating_tai.plmn.mnc_digit3 = 6;
  amf_ctx1.originating_tai.plmn.mnc_digit2 = 5;
  amf_ctx1.originating_tai.plmn.mnc_digit1 = 4;
  amf_ctx1.originating_tai.tac             = 1;

  amf_ctx1.ksi = 0x06;

  AmfNasStateConverter::amf_context_to_proto(&amf_ctx1, &emm_context_proto);
  AmfNasStateConverter::proto_to_amf_context(emm_context_proto, &amf_ctx2);

  EXPECT_EQ(amf_ctx1.imsi64, amf_ctx2.imsi64);
  EXPECT_EQ(amf_ctx1.saved_imsi64, amf_ctx2.saved_imsi64);
  EXPECT_EQ(amf_ctx1.amf_cause, amf_ctx2.amf_cause);
  EXPECT_EQ(amf_ctx1.m5gsregistrationtype, amf_ctx2.m5gsregistrationtype);
  EXPECT_EQ(amf_ctx1.member_present_mask, amf_ctx2.member_present_mask);
  EXPECT_EQ(amf_ctx1.member_valid_mask, amf_ctx2.member_valid_mask);
  EXPECT_EQ(amf_ctx1.is_dynamic, amf_ctx2.is_dynamic);
  EXPECT_EQ(amf_ctx1.is_registered, amf_ctx2.is_registered);
  EXPECT_EQ(
      amf_ctx1.is_initial_identity_imsi, amf_ctx2.is_initial_identity_imsi);
  EXPECT_EQ(
      amf_ctx1.is_guti_based_registered, amf_ctx2.is_guti_based_registered);
  EXPECT_EQ(amf_ctx1.is_imsi_only_detach, amf_ctx2.is_imsi_only_detach);
  EXPECT_EQ(memcmp(&amf_ctx1.imsi, &amf_ctx2.imsi, sizeof(amf_ctx1.imsi)), 0);
  EXPECT_EQ(amf_ctx1.imsi.u.num.digit1, amf_ctx2.imsi.u.num.digit1);
  EXPECT_EQ(amf_ctx1.amf_fsm_state, amf_ctx2.amf_fsm_state);
  EXPECT_EQ(memcmp(&amf_ctx1.imei, &amf_ctx2.imei, sizeof(amf_ctx1.imei)), 0);
  EXPECT_EQ(
      memcmp(&amf_ctx1.imeisv, &amf_ctx2.imeisv, sizeof(amf_ctx1.imeisv)), 0);
  EXPECT_EQ(amf_ctx1.ksi, amf_ctx2.ksi);
  EXPECT_EQ(
      memcmp(
          &amf_ctx1.originating_tai, &amf_ctx2.originating_tai,
          sizeof(amf_ctx1.originating_tai)),
      0);
}
}  // namespace magma5g
