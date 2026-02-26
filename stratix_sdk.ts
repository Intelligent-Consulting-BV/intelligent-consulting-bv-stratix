/**
 * @stratix/sdk
 * ============
 * JavaScript / TypeScript SDK for STRATIX schema integration
 * in web-based tooling and dashboard applications.
 *
 * © 2026 Intelligent Consulting BV. All rights reserved.
 * Author: Suzanne Natalie Button, Director, Intelligent Consulting BV
 * Licence: Apache 2.0 (implementation use); STRATIX name and specification
 *          remain the exclusive intellectual property of Intelligent Consulting BV.
 * First published: 26 February 2026
 */

// ─────────────────────────────────────────────────────────────
// Enumerations
// ─────────────────────────────────────────────────────────────

export enum IntentCategory {
  InitialAccess       = "initial_access",
  Execution           = "execution",
  Persistence         = "persistence",
  PrivilegeEscalation = "privilege_escalation",
  DefenceEvasion      = "defence_evasion",
  CredentialAccess    = "credential_access",
  Discovery           = "discovery",
  LateralMovement     = "lateral_movement",
  Collection          = "collection",
  CommandAndControl   = "command_and_control",
  Exfiltration        = "exfiltration",
  Impact              = "impact",
}

export enum KillChainPhase {
  Reconnaissance       = "reconnaissance",
  ResourceDevelopment  = "resource_development",
  Weaponisation        = "weaponisation",
  Delivery             = "delivery",
  Exploitation         = "exploitation",
  Installation         = "installation",
  CommandAndControl    = "command_and_control",
  ActionsOnObjectives  = "actions_on_objectives",
}

export enum DataClassification {
  Public       = "public",
  Internal     = "internal",
  Confidential = "confidential",
  Restricted   = "restricted",
  Sovereign    = "sovereign",
}

export enum NIS2Category {
  Essential   = "essential_entity",
  Important   = "important_entity",
  OutOfScope  = "out_of_scope",
}

export enum EUCSAssuranceLevel {
  Basic       = "basic",
  Substantial = "substantial",
  High        = "high",
}

export enum AIActClassification {
  Unacceptable = "unacceptable",
  HighRisk     = "high_risk",
  LimitedRisk  = "limited_risk",
  MinimalRisk  = "minimal_risk",
}

export enum GDPRLawfulBasis {
  Consent              = "consent",
  Contract             = "contract",
  LegalObligation      = "legal_obligation",
  VitalInterests       = "vital_interests",
  PublicTask           = "public_task",
  LegitimateInterests  = "legitimate_interests",
}

// ─────────────────────────────────────────────────────────────
// STRATIX Event interfaces
// ─────────────────────────────────────────────────────────────

export interface StratixIntentLayer {
  category:         IntentCategory;
  technique_id?:    string;          // ATT&CK technique e.g. T1078.003
  confidence_score?: number;         // 0–100
  kill_chain_phase?: KillChainPhase;
  blast_radius?:    string[];
}

export interface AccessLogEntry {
  accessor_id:  string;
  event_id:     string;
  purpose:      string;
  accessed_at:  string;            // ISO 8601
  entry_id:     string;
  signature:    string;            // SHA-256 of entry payload
}

export interface StratixSovereigntyLayer {
  data_residency?:       string;            // ISO 3166-1 alpha-2
  classification?:       DataClassification;
  gdpr_lawful_basis?:    GDPRLawfulBasis;
  nis2_category?:        NIS2Category;
  dora_ict_asset?:       boolean;
  eucs_assurance_level?: EUCSAssuranceLevel;
  ai_act_classification?: AIActClassification;
  access_log?:           AccessLogEntry[];
}

export interface StratixOTLayer {
  event_class:   string;
  asset_id?:     string;
  purdue_level?: 0 | 1 | 2 | 3 | 4 | 5;
  protocol?:     string;
  zone_from?:    number;
  zone_to?:      number;
  [key: string]: unknown;
}

export interface StratixAILayer {
  event_class:           string;
  model_id?:             string;
  model_version?:        string;
  inference_location?:   string;   // ISO 3166-1 alpha-2
  input_tokens?:         number;
  output_tokens?:        number;
  latency_ms?:           number;
  authorisation_boundary?: string;
  action_type?:          string;
  confidence?:           number;
  [key: string]: unknown;
}

export interface OCSFMetadata {
  version: string;
  product?: {
    name:    string;
    vendor:  string;
    version: string;
  };
  [key: string]: unknown;
}

export interface StratixEvent {
  // OCSF base (required)
  class_uid:    number;
  category_uid: number;
  time:         string;           // ISO 8601
  metadata:     OCSFMetadata;

  // STRATIX extension layers (optional)
  intent?:      StratixIntentLayer;
  sovereignty?: StratixSovereigntyLayer;
  ot?:          StratixOTLayer;
  ai?:          StratixAILayer;

  // Pass-through for additional OCSF fields
  [key: string]: unknown;
}

// ─────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────

export interface ValidationResult {
  valid:         boolean;
  errors:        string[];
  warnings:      string[];
  layerResults:  Record<string, boolean>;
}

const TECHNIQUE_PATTERN = /^T\d{4}(\.\d{3})?$/;
const ISO3166_PATTERN   = /^[A-Z]{2}$/;

export class StratixValidator {
  constructor(private strict: boolean = true) {}

  validate(event: Partial<StratixEvent>): ValidationResult {
    const result: ValidationResult = {
      valid: true,
      errors: [],
      warnings: [],
      layerResults: {},
    };

    const addError   = (msg: string) => { result.errors.push(msg); result.valid = false; };
    const addWarning = (msg: string) => result.warnings.push(msg);

    // OCSF base
    for (const field of ["class_uid", "category_uid", "time", "metadata"]) {
      if (!(field in (event as object))) addError(`OCSF base: missing required field '${field}'`);
    }
    if (event.time) {
      try { new Date(event.time).toISOString(); }
      catch { addError("OCSF base: 'time' must be ISO 8601 format"); }
    }
    result.layerResults["ocsf_base"] = result.errors.length === 0;

    // Layer 1: Intent
    if (!event.intent) {
      if (this.strict) addWarning("STRATIX Layer 1: 'intent' block absent");
      result.layerResults["intent"] = false;
    } else {
      const errsBefore = result.errors.length;
      const { category, technique_id, confidence_score, kill_chain_phase } = event.intent;
      if (!Object.values(IntentCategory).includes(category)) {
        addError(`intent.category '${category}' is not a valid STRATIX IntentCategory`);
      }
      if (technique_id && !TECHNIQUE_PATTERN.test(technique_id)) {
        addError("intent.technique_id must match ATT&CK pattern e.g. T1078 or T1078.003");
      }
      if (confidence_score !== undefined && (confidence_score < 0 || confidence_score > 100)) {
        addError("intent.confidence_score must be 0–100");
      }
      if (kill_chain_phase && !Object.values(KillChainPhase).includes(kill_chain_phase)) {
        addError(`intent.kill_chain_phase '${kill_chain_phase}' is not a valid KillChainPhase`);
      }
      result.layerResults["intent"] = result.errors.length === errsBefore;
    }

    // Layer 3: Sovereignty
    if (!event.sovereignty) {
      if (this.strict) addWarning("STRATIX Layer 3: 'sovereignty' block absent");
      result.layerResults["sovereignty"] = false;
    } else {
      const errsBefore = result.errors.length;
      const s = event.sovereignty;
      if (s.data_residency && !ISO3166_PATTERN.test(s.data_residency)) {
        addError("sovereignty.data_residency must be ISO 3166-1 alpha-2 e.g. 'BE'");
      }
      if (s.classification && !Object.values(DataClassification).includes(s.classification)) {
        addError(`sovereignty.classification '${s.classification}' is invalid`);
      }
      if (s.eucs_assurance_level && !Object.values(EUCSAssuranceLevel).includes(s.eucs_assurance_level)) {
        addError(`sovereignty.eucs_assurance_level '${s.eucs_assurance_level}' is invalid`);
      }
      result.layerResults["sovereignty"] = result.errors.length === errsBefore;
    }

    // Layer 2: OT (optional)
    if (event.ot) {
      const errsBefore = result.errors.length;
      const validOTClasses = [
        "plc_state_change","scada_alarm","process_deviation",
        "industrial_protocol_event","zone_crossing",
        "engineering_workstation_action","safety_system_event",
        "asset_inventory_change"
      ];
      if (!validOTClasses.includes(event.ot.event_class)) {
        addError(`ot.event_class '${event.ot.event_class}' is not a valid STRATIX OT event class`);
      }
      result.layerResults["ot"] = result.errors.length === errsBefore;
    } else {
      result.layerResults["ot"] = true;
    }

    // Layer 4: AI (optional)
    if (event.ai) {
      const errsBefore = result.errors.length;
      const validAIClasses = [
        "model_invocation","prompt_injection_attempt","tool_use",
        "decision_trace","autonomous_action","human_escalation",
        "model_drift_signal","governance_audit_record"
      ];
      if (!validAIClasses.includes(event.ai.event_class)) {
        addError(`ai.event_class '${event.ai.event_class}' is not a valid STRATIX AI event class`);
      }
      if (event.ai.inference_location && !ISO3166_PATTERN.test(event.ai.inference_location)) {
        addError("ai.inference_location must be ISO 3166-1 alpha-2");
      }
      if (event.ai.event_class === "autonomous_action") {
        if (!event.ai.authorisation_boundary) addError("ai.authorisation_boundary required for autonomous_action");
        if (!event.ai.action_type)            addError("ai.action_type required for autonomous_action");
      }
      result.layerResults["ai"] = result.errors.length === errsBefore;
    } else {
      result.layerResults["ai"] = true;
    }

    return result;
  }
}

// ─────────────────────────────────────────────────────────────
// Event builder — fluent API for constructing STRATIX events
// ─────────────────────────────────────────────────────────────

export class StratixEventBuilder {
  private event: Partial<StratixEvent> = {};

  setBase(classUid: number, categoryUid: number, metadata: OCSFMetadata): this {
    this.event.class_uid    = classUid;
    this.event.category_uid = categoryUid;
    this.event.time         = new Date().toISOString();
    this.event.metadata     = metadata;
    return this;
  }

  setIntent(intent: StratixIntentLayer): this {
    this.event.intent = intent;
    return this;
  }

  setSovereignty(sovereignty: StratixSovereigntyLayer): this {
    this.event.sovereignty = sovereignty;
    return this;
  }

  setOT(ot: StratixOTLayer): this {
    this.event.ot = ot;
    return this;
  }

  setAI(ai: StratixAILayer): this {
    this.event.ai = ai;
    return this;
  }

  build(): Partial<StratixEvent> {
    return { ...this.event };
  }

  buildAndValidate(strict = true): { event: Partial<StratixEvent>; result: ValidationResult } {
    const event  = this.build();
    const result = new StratixValidator(strict).validate(event);
    return { event, result };
  }
}

// ─────────────────────────────────────────────────────────────
// React hook (dashboard integration)
// ─────────────────────────────────────────────────────────────

/*
// Usage in a React dashboard component:
//
// import { useStratixValidator } from '@stratix/sdk';
//
// export function EventInspector({ event }: { event: unknown }) {
//   const result = useStratixValidator(event);
//   return (
//     <div>
//       <Badge colour={result.valid ? "green" : "red"}>
//         {result.valid ? "STRATIX Valid" : `${result.errors.length} errors`}
//       </Badge>
//       {result.errors.map(e => <p key={e}>{e}</p>)}
//     </div>
//   );
// }

export function useStratixValidator(event: unknown, strict = true): ValidationResult {
  // React: useMemo(() => new StratixValidator(strict).validate(event as Partial<StratixEvent>), [event, strict])
  return new StratixValidator(strict).validate(event as Partial<StratixEvent>);
}
*/

export default { StratixValidator, StratixEventBuilder };
