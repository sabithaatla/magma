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

#include "lte/gateway/c/core/oai/tasks/amf/amf_app_state_converter.h"
#include <vector>
#include <memory>
extern "C" {
#include "lte/gateway/c/core/oai/lib/message_utils/bytes_to_ie.h"
#include "lte/gateway/c/core/oai/common/conversions.h"
#include "lte/gateway/c/core/oai/common/dynamic_memory_check.h"
#include "lte/gateway/c/core/oai/lib/message_utils/ie_to_bytes.h"
#include "lte/gateway/c/core/oai/common/log.h"
}

using magma::lte::oai::MmeNasState;
namespace magma5g {

AmfNasStateConverter::AmfNasStateConverter()  = default;
AmfNasStateConverter::~AmfNasStateConverter() = default;

// HelperFunction: Converts guti_m5_t to std::string
std::string AmfNasStateConverter::amf_app_convert_guti_m5_to_string(
    const guti_m5_t& guti) {
#define GUTI_STRING_LEN 25
  char* temp_str =
      reinterpret_cast<char*>(calloc(1, sizeof(char) * GUTI_STRING_LEN));
  snprintf(
      temp_str, GUTI_STRING_LEN, "%x%x%x%x%x%x%02x%04x%04x%08x",
      guti.guamfi.plmn.mcc_digit1, guti.guamfi.plmn.mcc_digit2,
      guti.guamfi.plmn.mcc_digit3, guti.guamfi.plmn.mnc_digit1,
      guti.guamfi.plmn.mnc_digit2, guti.guamfi.plmn.mnc_digit3,
      guti.guamfi.amf_regionid, guti.guamfi.amf_set_id, guti.guamfi.amf_pointer,
      guti.m_tmsi);
  std::string guti_str(temp_str);
  free(temp_str);
  return guti_str;
}

// HelperFunction: Converts std:: string back to guti_m5_t
void AmfNasStateConverter::amf_app_convert_string_to_guti_m5(
    const std::string& guti_str, guti_m5_t* guti_m5_p) {
  int idx                   = 0;
  std::size_t chars_to_read = 1;
#define HEX_BASE_VAL 16
  guti_m5_p->guamfi.plmn.mcc_digit1 = std::stoul(
      guti_str.substr(idx++, chars_to_read), &chars_to_read, HEX_BASE_VAL);
  guti_m5_p->guamfi.plmn.mcc_digit2 = std::stoul(
      guti_str.substr(idx++, chars_to_read), &chars_to_read, HEX_BASE_VAL);
  guti_m5_p->guamfi.plmn.mcc_digit3 = std::stoul(
      guti_str.substr(idx++, chars_to_read), &chars_to_read, HEX_BASE_VAL);
  guti_m5_p->guamfi.plmn.mnc_digit1 = std::stoul(
      guti_str.substr(idx++, chars_to_read), &chars_to_read, HEX_BASE_VAL);
  guti_m5_p->guamfi.plmn.mnc_digit2 = std::stoul(
      guti_str.substr(idx++, chars_to_read), &chars_to_read, HEX_BASE_VAL);
  guti_m5_p->guamfi.plmn.mnc_digit3 = std::stoul(
      guti_str.substr(idx++, chars_to_read), &chars_to_read, HEX_BASE_VAL);
  chars_to_read                  = 2;
  guti_m5_p->guamfi.amf_regionid = std::stoul(
      guti_str.substr(idx, chars_to_read), &chars_to_read, HEX_BASE_VAL);
  idx += chars_to_read;
  chars_to_read                = 4;
  guti_m5_p->guamfi.amf_set_id = std::stoul(
      guti_str.substr(idx, chars_to_read), &chars_to_read, HEX_BASE_VAL);
  idx += chars_to_read;
  chars_to_read                 = 4;
  guti_m5_p->guamfi.amf_pointer = std::stoul(
      guti_str.substr(idx, chars_to_read), &chars_to_read, HEX_BASE_VAL);
  idx += chars_to_read;
  chars_to_read     = 8;
  guti_m5_p->m_tmsi = std::stoul(
      guti_str.substr(idx, chars_to_read), &chars_to_read, HEX_BASE_VAL);
}
// Converts Map<guti_m5_t,uint64_t> to proto
void AmfNasStateConverter::map_guti_uint64_to_proto(
    const map_guti_m5_uint64_t guti_map,
    google::protobuf::Map<std::string, uint64_t>* proto_map) {
  std::string guti_str;
  for (const auto& elm : guti_map.umap) {
    guti_str               = amf_app_convert_guti_m5_to_string(elm.first);
    (*proto_map)[guti_str] = elm.second;
  }
}

// Converts Proto to Map<guti_m5_t,uint64_t>
void AmfNasStateConverter::proto_to_guti_map(
    const google::protobuf::Map<std::string, uint64_t>& proto_map,
    map_guti_m5_uint64_t* guti_map) {
  for (auto const& kv : proto_map) {
    amf_ue_ngap_id_t amf_ue_ngap_id = kv.second;
    std::unique_ptr<guti_m5_t> guti = std::make_unique<guti_m5_t>();
    memset(guti.get(), 0, sizeof(guti_m5_t));
    // Converts guti to string.
    amf_app_convert_string_to_guti_m5(kv.first, guti.get());

    guti_m5_t guti_received = *guti.get();
    magma::map_rc_t m_rc    = guti_map->insert(guti_received, amf_ue_ngap_id);
    if (m_rc != magma::MAP_OK) {
      OAILOG_ERROR(
          LOG_AMF_APP,
          "Failed to insert amf_ue_ngap_id %lu in GUTI table, error: %s\n",
          amf_ue_ngap_id, map_rc_code2string(m_rc).c_str());
    }
  }
}

/*********************************************************
 *                AMF app state<-> Proto                  *
 * Functions to serialize/desearialize AMF app state      *
 * The caller is responsible for all memory management    *
 **********************************************************/

void AmfNasStateConverter::state_to_proto(
    const amf_app_desc_t* amf_nas_state_p, MmeNasState* state_proto) {
  OAILOG_FUNC_IN(LOG_AMF_APP);
  state_proto->set_mme_app_ue_s1ap_id_generator(
      amf_nas_state_p->amf_app_ue_ngap_id_generator);

  // These Functions are to be removed as part of the stateless enhancement
  // maps to proto
  auto amf_ue_ctxts_proto = state_proto->mutable_mme_ue_contexts();
  OAILOG_DEBUG(LOG_AMF_APP, "IMSI table to proto");
  magma::lte::StateConverter::map_uint64_uint64_to_proto(
      amf_nas_state_p->amf_ue_contexts.imsi_amf_ue_id_htbl,
      amf_ue_ctxts_proto->mutable_imsi_ue_id_htbl());
  magma::lte::StateConverter::map_uint64_uint64_to_proto(
      amf_nas_state_p->amf_ue_contexts.tun11_ue_context_htbl,
      amf_ue_ctxts_proto->mutable_tun11_ue_id_htbl());
  magma::lte::StateConverter::map_uint64_uint64_to_proto(
      amf_nas_state_p->amf_ue_contexts.gnb_ue_ngap_id_ue_context_htbl,
      amf_ue_ctxts_proto->mutable_enb_ue_id_ue_id_htbl());
  map_guti_uint64_to_proto(
      amf_nas_state_p->amf_ue_contexts.guti_ue_context_htbl,
      amf_ue_ctxts_proto->mutable_guti_ue_id_htbl());
  OAILOG_FUNC_OUT(LOG_AMF_APP);
}

void AmfNasStateConverter::proto_to_state(
    const MmeNasState& state_proto, amf_app_desc_t* amf_nas_state_p) {
  OAILOG_FUNC_IN(LOG_AMF_APP);
  amf_nas_state_p->amf_app_ue_ngap_id_generator =
      state_proto.mme_app_ue_s1ap_id_generator();

  if (amf_nas_state_p->amf_app_ue_ngap_id_generator == 0) {  // uninitialized
    amf_nas_state_p->amf_app_ue_ngap_id_generator = 1;
  }
  OAILOG_INFO(LOG_AMF_APP, "Done reading AMF statistics from data store");

  magma::lte::oai::MmeUeContext amf_ue_ctxts_proto =
      state_proto.mme_ue_contexts();

  amf_ue_context_t* amf_ue_ctxt_state = &amf_nas_state_p->amf_ue_contexts;

  // proto to maps
  OAILOG_INFO(LOG_AMF_APP, "Hashtable AMF UE ID => IMSI");
  proto_to_map_uint64_uint64(
      amf_ue_ctxts_proto.imsi_ue_id_htbl(),
      &amf_ue_ctxt_state->imsi_amf_ue_id_htbl);
  proto_to_map_uint64_uint64(
      amf_ue_ctxts_proto.tun11_ue_id_htbl(),
      &amf_ue_ctxt_state->tun11_ue_context_htbl);
  proto_to_map_uint64_uint64(
      amf_ue_ctxts_proto.enb_ue_id_ue_id_htbl(),
      &amf_ue_ctxt_state->gnb_ue_ngap_id_ue_context_htbl);

  proto_to_guti_map(
      amf_ue_ctxts_proto.guti_ue_id_htbl(),
      &amf_ue_ctxt_state->guti_ue_context_htbl);
  OAILOG_FUNC_OUT(LOG_AMF_APP);
}

void AmfNasStateConverter::ue_to_proto(
    const ue_m5gmm_context_t* ue_ctxt,
    magma::lte::oai::UeContext* ue_ctxt_proto) {
  ue_m5gmm_context_to_proto(ue_ctxt, ue_ctxt_proto);
}

void AmfNasStateConverter::proto_to_ue(
    const magma::lte::oai::UeContext& ue_ctxt_proto,
    ue_m5gmm_context_t* ue_ctxt) {
  proto_to_ue_m5gmm_context(ue_ctxt_proto, ue_ctxt);
}

/*********************************************************
 *                UE Context <-> Proto                    *
 * Functions to serialize/desearialize UE context         *
 * The caller needs to acquire a lock on UE context       *
 **********************************************************/

void AmfNasStateConverter::ue_m5gmm_context_to_proto(
    const ue_m5gmm_context_t* state_ue_m5gmm_context,
    magma::lte::oai::UeContext* ue_context_proto) {
  // Actual implementation logic will be added as part of upcoming pr
}

void AmfNasStateConverter::proto_to_ue_m5gmm_context(
    const magma::lte::oai::UeContext& ue_context_proto,
    ue_m5gmm_context_t* state_ue_m5gmm_context) {
  // Actual implementation logic will be added as part of upcoming pr
}

void AmfNasStateConverter::smf_proc_data_to_proto(
    const smf_proc_data_t* state_smf_proc_data,
    magma::lte::oai::Smf_Proc_Data* smf_proc_data_proto) {
  smf_proc_data_proto->set_pdu_session_id(state_smf_proc_data->pdu_session_id);
  smf_proc_data_proto->set_pti(state_smf_proc_data->pti);
  smf_proc_data_proto->set_message_type(state_smf_proc_data->message_type);
  smf_proc_data_proto->set_max_uplink(state_smf_proc_data->max_uplink);
  smf_proc_data_proto->set_max_downlink(state_smf_proc_data->max_downlink);
  smf_proc_data_proto->set_pdu_session_type(
      state_smf_proc_data->pdu_session_type);
  smf_proc_data_proto->set_ssc_mode(state_smf_proc_data->ssc_mode);
}
void AmfNasStateConverter::proto_to_smf_proc_data(
    const magma::lte::oai::Smf_Proc_Data& smf_proc_data_proto,
    smf_proc_data_t* state_smf_proc_data) {
  state_smf_proc_data->pdu_session_id = smf_proc_data_proto.pdu_session_id();
  state_smf_proc_data->pti            = smf_proc_data_proto.pti();
  state_smf_proc_data->message_type   = smf_proc_data_proto.message_type();
  state_smf_proc_data->max_uplink     = smf_proc_data_proto.max_uplink();
  state_smf_proc_data->max_downlink   = smf_proc_data_proto.max_downlink();
  state_smf_proc_data->pdu_session_type =
      smf_proc_data_proto.pdu_session_type();
  state_smf_proc_data->ssc_mode = smf_proc_data_proto.ssc_mode();
}

void AmfNasStateConverter::s_nssai_to_proto(
    const s_nssai_t* state_s_nssai, magma::lte::oai::SNssai* snassi_proto) {
  snassi_proto->set_sst(state_s_nssai->sst);
  snassi_proto->set_sd(*(uint32_t*) &state_s_nssai->sd);
}
void AmfNasStateConverter::proto_to_s_nssai(
    const magma::lte::oai::SNssai& snassi_proto, s_nssai_t* state_s_nssai) {
  state_s_nssai->sst              = snassi_proto.sst();
  *(uint32_t*) &state_s_nssai->sd = snassi_proto.sd();
}

void AmfNasStateConverter::pco_protocol_or_container_id_to_proto(
    const protocol_configuration_options_t&
        state_protocol_configuration_options,
    magma::lte::oai::ProtocolConfigurationOptions*
        protocol_configuration_options_proto) {
  for (int i = 0;
       i < state_protocol_configuration_options.num_protocol_or_container_id;
       i++) {
    pco_protocol_or_container_id_t state_pco_protocol_or_container_id =
        state_protocol_configuration_options.protocol_or_container_ids[i];
    auto pco_protocol_or_container_id_proto =
        protocol_configuration_options_proto->add_proto_or_container_id();
    pco_protocol_or_container_id_proto->set_id(
        state_pco_protocol_or_container_id.id);
    pco_protocol_or_container_id_proto->set_length(
        state_pco_protocol_or_container_id.length);
    if (state_pco_protocol_or_container_id.contents) {
      BSTRING_TO_STRING(
          state_pco_protocol_or_container_id.contents,
          pco_protocol_or_container_id_proto->mutable_contents());
    }
  }
}

void AmfNasStateConverter::proto_to_pco_protocol_or_container_id(
    const magma::lte::oai::ProtocolConfigurationOptions&
        protocol_configuration_options_proto,
    protocol_configuration_options_t* state_protocol_configuration_options) {
  auto proto_pco_ids =
      protocol_configuration_options_proto.proto_or_container_id();
  int i = 0;
  for (auto ptr = proto_pco_ids.begin(); ptr < proto_pco_ids.end(); ptr++) {
    pco_protocol_or_container_id_t* state_pco_protocol_or_container_id =
        &state_protocol_configuration_options->protocol_or_container_ids[i];
    state_pco_protocol_or_container_id->id     = ptr->id();
    state_pco_protocol_or_container_id->length = ptr->length();
    if (ptr->contents().length()) {
      state_pco_protocol_or_container_id->contents = bfromcstr_with_str_len(
          ptr->contents().c_str(), ptr->contents().length());
    }
    i++;
  }
}

void AmfNasStateConverter::protocol_configuration_options_to_proto(
    const protocol_configuration_options_t&
        state_protocol_configuration_options,
    magma::lte::oai::ProtocolConfigurationOptions*
        protocol_configuration_options_proto) {
  protocol_configuration_options_proto->set_ext(
      state_protocol_configuration_options.ext);
  protocol_configuration_options_proto->set_spare(
      state_protocol_configuration_options.spare);
  protocol_configuration_options_proto->set_config_protocol(
      state_protocol_configuration_options.configuration_protocol);
  protocol_configuration_options_proto->set_num_protocol_or_container_id(
      state_protocol_configuration_options.num_protocol_or_container_id);

  AmfNasStateConverter::pco_protocol_or_container_id_to_proto(
      state_protocol_configuration_options,
      protocol_configuration_options_proto);
}

void AmfNasStateConverter::proto_to_protocol_configuration_options(
    const magma::lte::oai::ProtocolConfigurationOptions&
        protocol_configuration_options_proto,
    protocol_configuration_options_t* state_protocol_configuration_options) {
  state_protocol_configuration_options->ext =
      protocol_configuration_options_proto.ext();
  state_protocol_configuration_options->spare =
      protocol_configuration_options_proto.spare();
  state_protocol_configuration_options->configuration_protocol =
      protocol_configuration_options_proto.config_protocol();
  state_protocol_configuration_options->num_protocol_or_container_id =
      protocol_configuration_options_proto.num_protocol_or_container_id();
  AmfNasStateConverter::proto_to_pco_protocol_or_container_id(
      protocol_configuration_options_proto,
      state_protocol_configuration_options);
}

void AmfNasStateConverter::session_ambr_to_proto(
    const session_ambr_t& state_session_ambr,
    magma::lte::oai::Ambr* ambr_proto) {
  ambr_proto->set_br_ul(state_session_ambr.ul_session_ambr);
  ambr_proto->set_br_dl(state_session_ambr.dl_session_ambr);
  ambr_proto->set_br_unit(static_cast<magma::lte::oai::Ambr::BitrateUnitsAMBR>(
      state_session_ambr.dl_ambr_unit));
}
void AmfNasStateConverter::proto_to_session_ambr(
    const magma::lte::oai::Ambr& ambr_proto,
    session_ambr_t* state_session_ambr) {
  state_session_ambr->dl_ambr_unit    = ambr_proto.br_unit();
  state_session_ambr->dl_session_ambr = ambr_proto.br_dl();
  state_session_ambr->ul_ambr_unit    = ambr_proto.br_unit();
  state_session_ambr->ul_session_ambr = ambr_proto.br_ul();
}

void AmfNasStateConverter::qos_flow_level_parameters_to_proto(
    const qos_flow_level_qos_parameters& state_qos_flow_parameters,
    magma::lte::oai::QosFlowParameters* qos_flow_parameters_proto) {
  qos_flow_parameters_proto->set_fiveqi(
      state_qos_flow_parameters.qos_characteristic.non_dynamic_5QI_desc.fiveQI);
  qos_flow_parameters_proto->set_priority_level(
      state_qos_flow_parameters.alloc_reten_priority.priority_level);
  qos_flow_parameters_proto->set_preemption_vulnerability(
      state_qos_flow_parameters.alloc_reten_priority.pre_emption_vul);
  qos_flow_parameters_proto->set_preemption_capability(
      state_qos_flow_parameters.alloc_reten_priority.pre_emption_cap);
}

void AmfNasStateConverter::proto_to_qos_flow_level_parameters(
    const magma::lte::oai::QosFlowParameters& qos_flow_parameters_proto,
    qos_flow_level_qos_parameters* state_qos_flow_parameters) {
  state_qos_flow_parameters->qos_characteristic.non_dynamic_5QI_desc.fiveQI =
      qos_flow_parameters_proto.fiveqi();
  state_qos_flow_parameters->alloc_reten_priority.priority_level =
      qos_flow_parameters_proto.priority_level();
  state_qos_flow_parameters->alloc_reten_priority.pre_emption_vul =
      static_cast<pre_emption_vulnerability>(
          qos_flow_parameters_proto.preemption_vulnerability());
  state_qos_flow_parameters->alloc_reten_priority.pre_emption_cap =
      static_cast<pre_emption_capability>(
          qos_flow_parameters_proto.preemption_capability());
}

void AmfNasStateConverter::qos_flow_setup_request_item_to_proto(
    const qos_flow_setup_request_item& state_qos_flow_request_item,
    magma::lte::oai::M5GQosFlowItem* qos_flow_item_proto) {
  qos_flow_item_proto->set_qfi(state_qos_flow_request_item.qos_flow_identifier);
  AmfNasStateConverter::qos_flow_level_parameters_to_proto(
      state_qos_flow_request_item.qos_flow_level_qos_param,
      qos_flow_item_proto->mutable_qos_flow_param());
}

void AmfNasStateConverter::proto_to_qos_flow_setup_request_item(
    const magma::lte::oai::M5GQosFlowItem& qos_flow_item_proto,
    qos_flow_setup_request_item* state_qos_flow_request_item) {
  state_qos_flow_request_item->qos_flow_identifier = qos_flow_item_proto.qfi();
  AmfNasStateConverter::proto_to_qos_flow_level_parameters(
      qos_flow_item_proto.qos_flow_param(),
      &state_qos_flow_request_item->qos_flow_level_qos_param);
}
// smf_context to proto and proto to smf_context
void AmfNasStateConverter::smf_context_to_proto(
    const smf_context_t* state_smf_context,
    magma::lte::oai::SmfContext* smf_context_proto) {
  smf_context_proto->set_sm_session_state(state_smf_context->pdu_session_state);
  smf_context_proto->set_pdu_session_version(
      state_smf_context->pdu_session_version);
  smf_context_proto->set_active_pdu_sessions(state_smf_context->n_active_pdus);
  smf_context_proto->set_is_emergency(state_smf_context->is_emergency);
  AmfNasStateConverter::session_ambr_to_proto(
      state_smf_context->selected_ambr,
      smf_context_proto->mutable_selected_ambr());

  smf_context_proto->set_gnb_gtp_teid(
      state_smf_context->gtp_tunnel_id.gnb_gtp_teid);

  char gnb_gtp_teid_ip_addr_str[16] = {0};
  inet_ntop(
      AF_INET, state_smf_context->gtp_tunnel_id.gnb_gtp_teid_ip_addr,
      gnb_gtp_teid_ip_addr_str, INET_ADDRSTRLEN);
  smf_context_proto->set_gnb_gtp_teid_ip_addr(gnb_gtp_teid_ip_addr_str);

  smf_context_proto->set_upf_gtp_teid(
      *(uint32_t*) &state_smf_context->gtp_tunnel_id.upf_gtp_teid);

  char upf_gtp_teid_ip_addr_str[16] = {0};
  inet_ntop(
      AF_INET, state_smf_context->gtp_tunnel_id.upf_gtp_teid_ip_addr,
      upf_gtp_teid_ip_addr_str, INET_ADDRSTRLEN);
  smf_context_proto->set_upf_gtp_teid_ip_addr(upf_gtp_teid_ip_addr_str);

  bstring bstr_buffer = paa_to_bstring(&state_smf_context->pdu_address);
  BSTRING_TO_STRING(bstr_buffer, smf_context_proto->mutable_paa());
  bdestroy(bstr_buffer);

  StateConverter::ambr_to_proto(
      state_smf_context->apn_ambr, smf_context_proto->mutable_apn_ambr());

  AmfNasStateConverter::smf_proc_data_to_proto(
      &state_smf_context->smf_proc_data,
      smf_context_proto->mutable_smf_proc_data());
  smf_context_proto->set_retransmission_count(
      state_smf_context->retransmission_count);
  AmfNasStateConverter::protocol_configuration_options_to_proto(
      state_smf_context->pco, smf_context_proto->mutable_pco());
  smf_context_proto->set_dnn_in_use(state_smf_context->dnn);

  AmfNasStateConverter::s_nssai_to_proto(
      &state_smf_context->requested_nssai,
      smf_context_proto->mutable_requested_nssai());

  AmfNasStateConverter::qos_flow_setup_request_item_to_proto(
      state_smf_context->subscribebed_qos_profile.qos_flow_req_item,
      smf_context_proto->mutable_qos_flow_list());
}

void AmfNasStateConverter::proto_to_smf_context(
    const magma::lte::oai::SmfContext& smf_context_proto,
    smf_context_t* state_smf_context) {
  state_smf_context->pdu_session_state =
      (SMSessionFSMState) smf_context_proto.sm_session_state();
  state_smf_context->pdu_session_version =
      smf_context_proto.pdu_session_version();
  state_smf_context->n_active_pdus = smf_context_proto.active_pdu_sessions();
  state_smf_context->is_emergency  = smf_context_proto.is_emergency();
  AmfNasStateConverter::proto_to_session_ambr(
      smf_context_proto.selected_ambr(), &state_smf_context->selected_ambr);
  state_smf_context->gtp_tunnel_id.gnb_gtp_teid =
      smf_context_proto.gnb_gtp_teid();

  memset(
      &state_smf_context->gtp_tunnel_id.gnb_gtp_teid_ip_addr, '\0',
      sizeof(state_smf_context->gtp_tunnel_id.gnb_gtp_teid_ip_addr));
  inet_pton(
      AF_INET, smf_context_proto.gnb_gtp_teid_ip_addr().c_str(),
      &(state_smf_context->gtp_tunnel_id.gnb_gtp_teid_ip_addr));

  *(uint32_t*) &state_smf_context->gtp_tunnel_id.upf_gtp_teid =
      smf_context_proto.upf_gtp_teid();

  memset(
      &state_smf_context->gtp_tunnel_id.upf_gtp_teid_ip_addr, '\0',
      sizeof(state_smf_context->gtp_tunnel_id.upf_gtp_teid_ip_addr));
  inet_pton(
      AF_INET, smf_context_proto.upf_gtp_teid_ip_addr().c_str(),
      &(state_smf_context->gtp_tunnel_id.upf_gtp_teid_ip_addr));

  bstring bstr_buffer;
  STRING_TO_BSTRING(smf_context_proto.paa(), bstr_buffer);
  bstring_to_paa(bstr_buffer, &state_smf_context->pdu_address);
  bdestroy(bstr_buffer);

  StateConverter::proto_to_ambr(
      smf_context_proto.apn_ambr(), &state_smf_context->apn_ambr);

  AmfNasStateConverter::proto_to_smf_proc_data(
      smf_context_proto.smf_proc_data(), &state_smf_context->smf_proc_data);

  state_smf_context->retransmission_count =
      smf_context_proto.retransmission_count();

  AmfNasStateConverter::proto_to_protocol_configuration_options(
      smf_context_proto.pco(), &state_smf_context->pco);

  state_smf_context->dnn = smf_context_proto.dnn_in_use();

  AmfNasStateConverter::proto_to_s_nssai(
      smf_context_proto.requested_nssai(), &state_smf_context->requested_nssai);

  AmfNasStateConverter::proto_to_qos_flow_setup_request_item(
      smf_context_proto.qos_flow_list(),
      &state_smf_context->subscribebed_qos_profile.qos_flow_req_item);
}

}  // namespace magma5g
