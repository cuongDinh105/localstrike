"""
scope/engine.py: Deterministic Scope Enforcement Engine for LocalStrike.
Ensures all agent actions adhere to the defined assessment scope.
"""

import logging
import ipaddress
from typing import List, Optional, Dict, Any, Literal, Union
from pydantic import BaseModel, Field, PrivateAttr, ValidationError

# For type hinting internal_action and SemanticValidationResult
from schemas.action import LLMInternalAction, ToolExecutionAction, StateUpdateAction, ReportGenerationAction, SemanticValidationResult

# Import AssetGraphEngine
from asset_graph.engine import AssetGraphEngine

logger = logging.getLogger(__name__)

class ScopeDefinition(BaseModel):
    """
    Defines the boundaries and rules for the penetration test scope.
    """
    initial_target_value: str = Field(..., description="The initial target value for the assessment.")
    allowed_domains: List[str] = Field(default_factory=list, description="List of root domains (e.g., 'example.com') that are in scope.")
    allowed_ip_ranges: List[str] = Field(default_factory=list, description="List of IP CIDR ranges (e.g., '192.168.1.0/24') that are in scope.")
    excluded_assets: List[str] = Field(default_factory=list, description="List of specific assets (domains, IPs) that are explicitly out of scope.")
    max_depth: int = Field(5, description="Maximum 'depth' of reconnaissance or exploitation from initial target.")
    scan_intensity_level: Literal["low", "medium", "high"] = Field("medium", description="General intensity level for scanning actions.")

    # Compiled for faster lookup (machine-only visibility)
    _compiled_allowed_domains: Set[str] = PrivateAttr(default_factory=set) 
    _compiled_allowed_ip_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = PrivateAttr(default_factory=list)

    def __init__(self, **data: Any):
        super().__init__(**data)
        self._compiled_allowed_domains = {d.lower().lstrip('.') for d in self.allowed_domains} # Normalize domains to a set
        self._compiled_allowed_ip_networks = []
        for ip_range in self.allowed_ip_ranges:
            try:
                self._compiled_allowed_ip_networks.append(ipaddress.ip_network(ip_range, strict=False))
            except ValueError:
                logger.warning(f"Invalid IP range in scope definition: {ip_range}. Skipping.")

    # Helper methods, now used by AssetGraphEngine as well
    def is_domain_in_allowed_scope(self, target_domain: str) -> bool:
        """Checks if a domain is within the allowed domains."""
        target_domain_normalized = target_domain.lower().lstrip('.')
        for allowed_root in self._compiled_allowed_domains:
            if target_domain_normalized == allowed_root or target_domain_normalized.endswith(f".{allowed_root}"):
                return True
        return False

    def is_ip_in_allowed_scope(self, target_ip_str: str) -> bool:
        """Checks if an IP address is within the allowed IP ranges."""
        try:
            target_ip = ipaddress.ip_address(target_ip_str)
            for allowed_network in self._compiled_allowed_ip_networks:
                if target_ip in allowed_network:
                    return True
        except ValueError:
            return False # Not a valid IP address or cannot be in IP scope
        return False


class ScopeValidationResult(BaseModel):
    """
    Result of a scope validation check for a proposed action.
    """
    is_allowed: bool = Field(..., description="True if the action is within scope, False otherwise.")
    violation_type: Optional[str] = Field(None, description="Type of scope violation (e.g., 'OUT_OF_DOMAIN', 'EXCLUDED_ASSET', 'MAX_DEPTH_EXCEEDED').")
    violation_reason: Optional[str] = Field(None, description="Detailed reason for the scope violation.")
    # New field to carry semantic validation results
    semantic_validation: Optional[SemanticValidationResult] = Field(None, description="Result from the semantic validation engine.")


class ScopeEngine:
    """
    Determines if a proposed action adheres to the defined assessment scope.
    This is a deterministic, non-LLM, non-MCP component.
    It integrates semantic validation from AssetGraphEngine.
    """
    def __init__(self, scope_definition: ScopeDefinition, asset_graph_engine: AssetGraphEngine):
        self.scope_definition = scope_definition
        self.asset_graph_engine = asset_graph_engine
        logger.info("ScopeEngine initialized with definition:")
        logger.info(self.scope_definition.model_dump_json(indent=2))

    def _get_target_from_action(self, internal_action: LLMInternalAction) -> Optional[str]:
        """
        Extracts the primary target from an LLMInternalAction if applicable.
        """
        action_details = internal_action.action
        target = None
        if isinstance(action_details, ToolExecutionAction):
            target = action_details.parameters.get("target")
        # TODO: Potentially extract target from StateUpdate actions if they imply a target change
        return str(target) if target else None

    def _is_excluded(self, target: str) -> bool:
        """Checks if the target is in the excluded assets list."""
        return target.lower() in [e.lower() for e in self.scope_definition.excluded_assets]


    def validate_action(self, internal_action: LLMInternalAction, current_state_snapshot: Dict[str, Any]) -> ScopeValidationResult:
        """
        Validates a proposed LLMInternalAction against the defined scope,
        integrating deterministic checks and semantic validation.
        """
        action = internal_action.action
        
        # Actions that don't involve a specific target (e.g., StateUpdate, ReportGeneration)
        # are generally considered in scope unless their parameters are problematic.
        if isinstance(action, (StateUpdateAction, ReportGenerationAction)):
            # TODO: More granular checks for internal commands (e.g., ensure state update doesn't target excluded asset)
            return ScopeValidationResult(is_allowed=True)

        # For ToolExecutionAction, a target is expected
        if not isinstance(action, ToolExecutionAction):
            return ScopeValidationResult(is_allowed=True, violation_type="UNEXPECTED_ACTION_TYPE", violation_reason="Non-ToolExecution action passed through target validation logic improperly.")

        target = self._get_target_from_action(internal_action)
        if not target:
            # No target specified, assume in scope if not an execution on a target
            return ScopeValidationResult(is_allowed=True)

        # 1. Check Excluded Assets (C) - Deterministic String Match
        if self._is_excluded(target):
            return ScopeValidationResult(is_allowed=False, violation_type="EXCLUDED_ASSET", violation_reason=f"Target '{target}' is explicitly excluded from scope.")
        
        # 2. Perform Semantic Validation using AssetGraphEngine
        semantic_result = self.asset_graph_engine.semantic_validate_target(
            target_value=target,
            state_manager_snapshot=current_state_snapshot, # Pass full snapshot for context
            initial_target_value=self.scope_definition.initial_target_value # Pass initial target for root
        )

        if not semantic_result.is_valid:
            # Semantic validation failed, so action is not allowed.
            return ScopeValidationResult(
                is_allowed=False, 
                violation_type=semantic_result.semantic_violation_reason, # Use semantic violation type
                violation_reason=f"Semantic validation failed for target '{target}': {semantic_result.semantic_violation_reason}",
                semantic_validation=semantic_result
            )

        # If semantic validation passed, the target is semantically valid and in scope
        return ScopeValidationResult(is_allowed=True, semantic_validation=semantic_result)

```