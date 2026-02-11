"""
asset_graph/engine.py: Manages the Asset Relationship Graph and performs semantic validation.
"""

import logging
import ipaddress
import hashlib
from datetime import datetime
from typing import List, Optional, Dict, Any, Literal, Union, Set, Tuple
from pydantic import BaseModel, Field, PrivateAttr, validate_call

# For type hinting ScopeDefinition
# from scope.engine import ScopeDefinition
# We need to import ScopeDefinition without circular dependency, so we'll use a forward reference or Any for now.

logger = logging.getLogger(__name__)

class AssetNode(BaseModel):
    """Represents a single asset in the graph."""
    asset_id: str = Field(..., description="Unique ID for the asset (hash of type+value).")
    asset_type: Literal["domain", "subdomain", "ip", "url", "service", "email", "person", "organization", "other"] = Field(..., description="Type of the asset.")
    value: str = Field(..., description="The actual value of the asset (e.g., 'example.com', '192.168.1.1').")
    parent_asset_id: Optional[str] = Field(None, description="ID of the asset from which this asset was discovered/derived.")
    discovery_source_action_id: Optional[str] = Field(None, description="ID of the action that discovered this asset.")
    discovery_timestamp: datetime = Field(default_factory=datetime.now)
    in_scope: bool = Field(False, description="True if this asset is considered in scope.")
    risk_score: float = Field(0.0, description="Calculated risk score for the asset.")

    # Cached for efficiency, machine-only visibility
    _ip_address: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = PrivateAttr(default=None)
    _domain_parts: Optional[List[str]] = PrivateAttr(default=None)

    def __init__(self, **data: Any):
        super().__init__(**data)
        if self.asset_type == "ip":
            try:
                self._ip_address = ipaddress.ip_address(self.value)
            except ValueError:
                logger.warning(f"AssetNode created with invalid IP value: {self.value}")
        elif "domain" in self.asset_type:
            self._domain_parts = self.value.lower().split('.')

    @staticmethod
    def generate_asset_id(asset_type: str, value: str) -> str:
        """Generates a consistent asset_id."""
        return hashlib.sha256(f"{asset_type}:{value}".encode('utf-8')).hexdigest()

class AssetRelationship(BaseModel):
    """Represents a directed relationship between two assets."""
    source_asset_id: str
    target_asset_id: str
    relationship_type: Literal["dns_resolves_to", "subdomain_of", "hosts_service", "linked_to", "owns", "belongs_to", "contains"] = Field(..., description="Type of relationship.")
    timestamp: datetime = Field(default_factory=datetime.now)

class SemanticValidationResult(BaseModel):
    """Result of semantic validation for a proposed target."""
    is_valid: bool = Field(..., description="True if the target is semantically valid and in scope.")
    inferred_asset_type: Optional[str] = Field(None, description="Inferred type of the target (e.g., 'domain', 'ip', 'url').")
    computed_depth: Optional[int] = Field(None, description="Calculated depth of the target from the initial scope roots.")
    semantic_violation_reason: Optional[str] = Field(None, description="Detailed reason for semantic violation, if any.")
    resolved_ip: Optional[str] = Field(None, description="Resolved IP address if target was a domain.")
    resolved_asset_id: Optional[str] = Field(None, description="Asset ID of the target after resolution/inference.")

class AssetGraphEngine:
    """
    Manages the Asset Relationship Graph and provides semantic validation capabilities.
    """
    def __init__(self, scope_definition: Any): # Using Any to avoid circular dependency with ScopeDefinition
        self.asset_nodes: Dict[str, AssetNode] = {}
        self.relationships: Dict[str, List[AssetRelationship]] = {} # source_asset_id -> list of relationships
        self.scope_definition = scope_definition # Reference to ScopeDefinition for validation rules

        self._dns_cache: Dict[str, str] = {} # Mock DNS cache: domain -> IP (for deterministic testing)
        logger.info("AssetGraphEngine initialized.")

    def add_asset(self, asset_type: str, value: str, parent_asset_id: Optional[str] = None, 
                  discovery_action_id: Optional[str] = None, in_scope: bool = False) -> AssetNode:
        """Adds a new asset to the graph or updates an existing one."""
        asset_id = AssetNode.generate_asset_id(asset_type, value)
        if asset_id not in self.asset_nodes:
            node = AssetNode(
                asset_id=asset_id,
                asset_type=asset_type,
                value=value,
                parent_asset_id=parent_asset_id,
                discovery_source_action_id=discovery_action_id,
                in_scope=in_scope
            )
            self.asset_nodes[asset_id] = node
            self.relationships[asset_id] = [] # Initialize relationships list
            logger.debug(f"Added new asset to graph: {asset_type}:{value} (ID: {asset_id})")
        else:
            node = self.asset_nodes[asset_id]
            # Update in_scope if it changes to True
            if in_scope and not node.in_scope:
                node.in_scope = True
                logger.debug(f"Updated in_scope status for asset {asset_id} to True.")
        return node

    def add_relationship(self, source_asset_id: str, target_asset_id: str, 
                         relationship_type: Literal["dns_resolves_to", "subdomain_of", "hosts_service", "linked_to", "owns", "belongs_to", "contains"]):
        """Adds a directed relationship between two assets."""
        if source_asset_id not in self.asset_nodes or target_asset_id not in self.asset_nodes:
            logger.warning(f"Cannot add relationship: source ({source_asset_id}) or target ({target_asset_id}) asset not found.")
            return

        rel = AssetRelationship(source_asset_id=source_asset_id, target_asset_id=target_asset_id, relationship_type=relationship_type)
        # Prevent duplicate relationships
        if rel not in self.relationships[source_asset_id]:
            self.relationships[source_asset_id].append(rel)
            logger.debug(f"Added relationship {relationship_type} from {source_asset_id} to {target_asset_id}")
        else:
            logger.debug(f"Relationship {relationship_type} from {source_asset_id} to {target_asset_id} already exists.")


    def get_asset_depth(self, asset_id: str, root_asset_id: str) -> Optional[int]:
        """
        Calculates the shortest path depth of an asset from a root asset using BFS.
        Depth 0 is the root asset itself.
        """
        if asset_id == root_asset_id:
            return 0
        if asset_id not in self.asset_nodes or root_asset_id not in self.asset_nodes:
            return None # Asset or root not in graph

        q = [(root_asset_id, 0)] # (asset_id, current_depth)
        visited = {root_asset_id}

        while q:
            current_id, depth = q.pop(0)

            # Check relationships FROM current_id TO others
            for rel in self.relationships.get(current_id, []):
                if rel.target_asset_id == asset_id:
                    return depth + 1
                if rel.target_asset_id not in visited:
                    visited.add(rel.target_asset_id)
                    q.append((rel.target_asset_id, depth + 1))
            
            # Also check relationships TO current_id FROM others (e.g. subdomain_of)
            # This is more complex for direct adjacency list, requires iterating all relationships
            # For simplicity, we'll only do outgoing relationships in BFS for now.
            # A full bidirectional graph would require an inverse adjacency list.
            # For "subdomain_of", the relationship points from subdomain to root, so
            # we need to find paths FROM root TO subdomain.
            # Let's adjust for "subdomain_of" specifically.
            for node_id, node_rels in self.relationships.items():
                for rel in node_rels:
                    if rel.relationship_type == "subdomain_of" and rel.source_asset_id == current_id and rel.target_asset_id == asset_id:
                        return depth + 1 # Subdomain_of points from sub to parent, so reverse for depth
                    if rel.relationship_type == "dns_resolves_to" and rel.source_asset_id == current_id and rel.target_asset_id == asset_id:
                        return depth + 1

                    # Re-evaluate the BFS to correctly handle parent-child relationships like subdomain_of
                    # We need to find paths where the target is a direct descendant or DNS resolution
                    # Let's assume relationships are defined as parent -> child for depth calculation
                    # e.g., domain A has subdomain B (A --subdomain_of--> B)
                    # or domain A resolves to IP B (A --dns_resolves_to--> B)

        # If not found, check direct parental relationship for depth 1
        for node in self.asset_nodes.values():
            if node.asset_id == asset_id and node.parent_asset_id == root_asset_id:
                return 1

        return None # Not reachable from root_asset_id

    def _infer_asset_type(self, value: str) -> Literal["domain", "ip", "url", "other"]:
        """Infers the asset type based on its string value."""
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass
        if value.startswith(("http://", "https://")):
            return "url"
        if "." in value: # Simple check for domain
            return "domain"
        return "other"

    def _mock_dns_resolve(self, domain: str) -> Optional[str]:
        """
        Mocks a DNS resolution for deterministic testing.
        In a real scenario, this would call a DNS resolver.
        For deterministic testing, we can pre-populate a cache.
        """
        # For adversarial testing, can introduce fake resolutions
        # For now, a simple placeholder or pre-defined mock
        # Example: self._dns_cache["test.example.com"] = "192.168.1.5"
        return self._dns_cache.get(domain)

    @validate_call
    def semantic_validate_target(self, target_value: str, state_manager_snapshot: Dict[str, Any], discovery_action_id: str) -> SemanticValidationResult:
        """
        Performs semantic validation for a proposed target, integrating with the asset graph.
        (Part 2: Semantic Validation)
        """
        inferred_type = self._infer_asset_type(target_value)
        resolved_ip: Optional[str] = None
        computed_depth: Optional[int] = None
        target_asset_id = AssetNode.generate_asset_id(inferred_type, target_value)

        # 0. Pre-check: If asset already exists and is blocked or out of scope
        if target_asset_id in self.asset_nodes:
            node = self.asset_nodes[target_asset_id]
            if not node.in_scope:
                return SemanticValidationResult(is_valid=False, inferred_asset_type=inferred_type, semantic_violation_reason=f"Asset '{target_value}' (ID: {target_asset_id}) is already known and marked out of scope.", resolved_asset_id=target_asset_id)
            # If in scope, no further semantic violation for this check
            if node.in_scope and node.computed_depth is not None:
                return SemanticValidationResult(is_valid=True, inferred_asset_type=inferred_type, computed_depth=node.computed_depth, resolved_asset_id=target_asset_id)


        # 1. Cross-type Target Ambiguity / Initial Asset Creation
        # If target is a URL, extract domain/IP for further checks
        if inferred_type == "url":
            parsed_url = urllib.parse.urlparse(target_value)
            if parsed_url.hostname:
                # Re-infer type based on hostname
                host_type = self._infer_asset_type(parsed_url.hostname)
                if host_type == "ip":
                    inferred_type = "ip"
                    target_value = parsed_url.hostname
                elif host_type == "domain":
                    inferred_type = "domain"
                    target_value = parsed_url.hostname
                else: # Fallback
                    return SemanticValidationResult(is_valid=False, inferred_asset_type="url", semantic_violation_reason=f"URL '{target_value}' points to an unhandleable host type.", resolved_asset_id=target_asset_id)
            else:
                return SemanticValidationResult(is_valid=False, inferred_asset_type="url", semantic_violation_reason=f"URL '{target_value}' has no valid hostname.", resolved_asset_id=target_asset_id)
        
        # Now target_value and inferred_type are for a domain or IP

        # 2. DNS Resolution Drift (if target is a domain)
        if inferred_type == "domain":
            resolved_ip = self._mock_dns_resolve(target_value)
            if resolved_ip:
                # Check if resolved IP is in allowed_ip_ranges
                if not self._is_ip_in_scope(resolved_ip):
                    return SemanticValidationResult(is_valid=False, inferred_asset_type="domain", semantic_violation_reason=f"DNS_RESOLUTION_OUT_OF_SCOPE: Domain '{target_value}' resolves to IP '{resolved_ip}' which is outside allowed IP ranges.", resolved_ip=resolved_ip, resolved_asset_id=target_asset_id)
            else:
                # If cannot resolve, it's a semantic violation for now (can be softened later)
                return SemanticValidationResult(is_valid=False, inferred_asset_type="domain", semantic_violation_reason=f"DNS_RESOLUTION_FAILED: Domain '{target_value}' could not be resolved.", resolved_asset_id=target_asset_id)

        # 3. Asset Lineage Depth
        # This requires the asset to be in the graph already for parent_asset_id to be set
        # For new targets, we determine depth from initial_target if it's a subdomain.
        
        root_asset_id = AssetNode.generate_asset_id(self._infer_asset_type(self.scope_definition.initial_target_value), self.scope_definition.initial_target_value)
        
        # Check if it's a known asset, otherwise it's depth 1 from root if it's allowed
        if target_asset_id in self.asset_nodes:
            computed_depth = self.get_asset_depth(target_asset_id, root_asset_id)
        else:
            # New asset: If it's a direct subdomain of an allowed domain (depth 1) or IP within allowed range (depth 1)
            # This is where we link back to the ScopeEngine's string-based checks temporarily for new assets
            if inferred_type == "domain" and self.scope_definition._is_domain_in_scope(target_value):
                computed_depth = 1 # Treat as directly linked to root scope
            elif inferred_type == "ip" and self.scope_definition._is_ip_in_scope(target_value):
                computed_depth = 1 # Treat as directly linked to root scope
            else:
                # If it's not a known asset and not a direct part of the initial scope (depth 1),
                # it might be deeper or an entirely new root. Need to link it to its parent.
                # For this validation, if it's not directly inferable as depth 0 or 1, we block it for now
                return SemanticValidationResult(is_valid=False, inferred_asset_type=inferred_type, semantic_violation_reason=f"DISCONNECTED_ASSET: Target '{target_value}' is not a known asset and cannot be linked to the initial scope roots for depth calculation.", resolved_asset_id=target_asset_id)

        if computed_depth is not None and computed_depth > self.scope_definition.max_depth:
            return SemanticValidationResult(is_valid=False, inferred_asset_type=inferred_type, computed_depth=computed_depth, semantic_violation_reason=f"MAX_DEPTH_EXCEEDED: Target '{target_value}' (depth {computed_depth}) exceeds max allowed depth of {self.scope_definition.max_depth}.", resolved_asset_id=target_asset_id)
        
        # 4. Discovered Asset Scope Creep (implicitly handled by previous checks for new assets)
        # If an asset is discovered and it passes domain/IP checks and depth, it's considered fine.
        # If it's not linked to an in-scope asset, it would be blocked by depth/disconnected.

        # If all checks pass
        return SemanticValidationResult(is_valid=True, inferred_asset_type=inferred_type, computed_depth=computed_depth, resolved_ip=resolved_ip, resolved_asset_id=target_asset_id)


    def _get_parent_asset(self, asset_node: AssetNode) -> Optional[AssetNode]:
        """Helper to get parent asset, mainly for subdomain_of relationships."""
        if asset_node.asset_type == "subdomain" and asset_node._domain_parts:
            # Try to infer root domain as parent
            if len(asset_node._domain_parts) > 2: # e.g., sub.example.com
                parent_value = ".".join(asset_node._domain_parts[1:])
                parent_id = AssetNode.generate_asset_id("domain", parent_value)
                return self.asset_nodes.get(parent_id)
        return None

    def _update_in_scope_status(self, asset_id: str, is_in_scope: bool):
        """Updates the in_scope status of an asset node."""
        if asset_id in self.asset_nodes:
            self.asset_nodes[asset_id].in_scope = is_in_scope

```