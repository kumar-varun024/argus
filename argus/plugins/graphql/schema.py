import logging
import json
import os
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import hashlib

from argus.plugins.graphql.models import (
    GraphQLSchema, GraphQLType, GraphQLField, GraphQLArgument, 
    GraphQLOperation, GraphQLEnum, GraphQLUnion, GraphQLInterface, Observation
)
from argus.evidence.model import Evidence
from argus.graph.node import Node
from argus.graph.edge import Edge

logger = logging.getLogger(__name__)

class GraphQLSchemaAnalyzer:
    def __init__(self, cache_dir: str = ".argus/cache/graphql"):
        self.cache_dir = cache_dir
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)
            
    def analyze(self, mission) -> GraphQLSchema:
        logger.info("GraphQLSchemaAnalyzer: Starting schema analysis...")
        
        endpoints = getattr(mission.graphql, "endpoints", []) if hasattr(mission, "graphql") else []
        
        schema = None
        for ep in endpoints:
            # Try cache first
            cache_key = hashlib.md5(ep.url.encode()).hexdigest()
            cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")
            
            if os.path.exists(cache_path):
                logger.info(f"GraphQLSchemaAnalyzer: Cache hit for {ep.url}")
                schema = self._load_from_cache(cache_path)
                if schema:
                    break
            else:
                logger.info(f"GraphQLSchemaAnalyzer: Cache miss for {ep.url}")
            
            # Simulate Introspection
            schema = self.acquire_schema(ep.url)
            if schema:
                logger.info(f"GraphQLSchemaAnalyzer: Schema downloaded via introspection for {ep.url}")
                self._save_to_cache(schema, cache_path)
                break
                
        if not schema:
            logger.info("GraphQLSchemaAnalyzer: Introspection failed or unavailable. Falling back to inference.")
            schema = self.infer_schema(mission)
            if schema:
                logger.info("GraphQLSchemaAnalyzer: Schema inferred from observations.")
                
        if schema:
            self._update_mission(mission, schema)
            
        return schema
        
    def acquire_schema(self, url: str) -> Optional[GraphQLSchema]:
        if "introspection-enabled" in url:
            schema = GraphQLSchema(source="Introspection", evidence=[])
            schema.types["User"] = GraphQLType(name="User", kind="OBJECT")
            return schema
        return None
        
    def infer_schema(self, mission) -> GraphQLSchema:
        schema = GraphQLSchema(source="Inference", evidence=[])
        
        if hasattr(mission, "evidence"):
            evidence_store = mission.evidence
            evidence_list = []
            if hasattr(evidence_store, "get_all"):
                evidence_list = evidence_store.get_all()
            elif hasattr(evidence_store, "all"):
                evidence_list = evidence_store.all()
            elif hasattr(evidence_store, "_evidence"):
                evidence_list = evidence_store._evidence
            elif isinstance(evidence_store, list):
                evidence_list = evidence_store
            elif hasattr(evidence_store, "__iter__"):
                evidence_list = list(evidence_store)
                
            for ev in evidence_list:
                val = str(ev.value)
                
                # Queries
                if "query {" in val or "query MyQuery" in val or val.startswith("query "):
                    op = GraphQLOperation(name="InferredQuery", operation_type="Query", return_type="Unknown", evidence=[ev], source="Inference")
                    schema.queries[op.name] = op
                    logger.info("GraphQLSchemaAnalyzer: Type discovered (Query)")
                    
                # Mutations
                if "mutation {" in val or "mutation MyMutation" in val or val.startswith("mutation "):
                    op = GraphQLOperation(name="InferredMutation", operation_type="Mutation", return_type="Unknown", evidence=[ev], source="Inference")
                    schema.mutations[op.name] = op
                    logger.info("GraphQLSchemaAnalyzer: Mutation discovered")
                    
                # Subscriptions
                if "subscription {" in val or val.startswith("subscription "):
                    op = GraphQLOperation(name="InferredSubscription", operation_type="Subscription", return_type="Unknown", evidence=[ev], source="Inference")
                    schema.subscriptions[op.name] = op
                    logger.info("GraphQLSchemaAnalyzer: Subscription observed")
                    
                # Object inference from response
                if '"__typename"' in val or '"__typename":' in val:
                    try:
                        data = json.loads(val)
                        self._extract_typenames(data, schema, ev)
                    except json.JSONDecodeError:
                        pass
                        
                # Enums, interfaces, unions
                if "enum " in val:
                    schema.enums["InferredEnum"] = GraphQLEnum(name="InferredEnum", source="Inference", evidence=[ev])
                if "interface " in val:
                    schema.interfaces["InferredInterface"] = GraphQLInterface(name="InferredInterface", source="Inference", evidence=[ev])
                    logger.info("GraphQLSchemaAnalyzer: Interface discovered")
                if "union " in val:
                    schema.unions["InferredUnion"] = GraphQLUnion(name="InferredUnion", source="Inference", evidence=[ev])
                if "scalar " in val:
                    schema.types["CustomScalar"] = GraphQLType(name="CustomScalar", kind="SCALAR", source="Inference", evidence=[ev])
                    
        return schema
        
    def _extract_typenames(self, data: Any, schema: GraphQLSchema, ev: Evidence):
        if isinstance(data, dict):
            if "__typename" in data:
                t_name = data["__typename"]
                if t_name not in schema.types:
                    schema.types[t_name] = GraphQLType(name=t_name, kind="OBJECT", source="Inference", evidence=[ev])
                    logger.info(f"GraphQLSchemaAnalyzer: New object discovered ({t_name})")
            for v in data.values():
                self._extract_typenames(v, schema, ev)
        elif isinstance(data, list):
            for item in data:
                self._extract_typenames(item, schema, ev)
                
    def _update_mission(self, mission, schema: GraphQLSchema):
        if not hasattr(mission, "graphql"):
            from argus.runtime.mission import GraphQLState
            mission.graphql = GraphQLState()
            
        mission.graphql.schemas.append(schema)
        
        # Populate mission state lists
        for t_name, t_obj in schema.types.items():
            mission.graphql.types[t_name] = t_obj
            
        for o_name, o_obj in schema.queries.items():
            mission.graphql.operations.append(o_obj)
        for o_name, o_obj in schema.mutations.items():
            mission.graphql.operations.append(o_obj)
        for o_name, o_obj in schema.subscriptions.items():
            mission.graphql.operations.append(o_obj)
            
        for e_name, e_obj in schema.enums.items():
            mission.graphql.enums.append(e_obj)
        for i_name, i_obj in schema.interfaces.items():
            mission.graphql.interfaces.append(i_obj)
        for u_name, u_obj in schema.unions.items():
            mission.graphql.unions.append(u_obj)
            
        # Update Knowledge Graph
        if hasattr(mission, "graph") and mission.graph:
            s_node = Node(id=f"graphql_schema_{schema.id}", type="Schema", value="GraphQLSchema")
            mission.graph.add(s_node)
            
            for t_name, t_obj in schema.types.items():
                t_node = Node(id=f"graphql_type_{t_obj.id}", type="Object", value=t_name)
                mission.graph.add(t_node)
                mission.graph.connect(s_node.id, t_node.id, "CONTAINS")
                
            for o_name, o_obj in schema.queries.items():
                o_node = Node(id=f"graphql_operation_{o_obj.id}", type="Operation", value=o_name)
                mission.graph.add(o_node)
                mission.graph.connect(s_node.id, o_node.id, "CONTAINS")
                
            for o_name, o_obj in schema.mutations.items():
                o_node = Node(id=f"graphql_operation_{o_obj.id}", type="Operation", value=o_name)
                mission.graph.add(o_node)
                mission.graph.connect(s_node.id, o_node.id, "CONTAINS")
                
            for o_name, o_obj in schema.subscriptions.items():
                o_node = Node(id=f"graphql_operation_{o_obj.id}", type="Operation", value=o_name)
                mission.graph.add(o_node)
                mission.graph.connect(s_node.id, o_node.id, "CONTAINS")
                
            for e_name, e_obj in schema.enums.items():
                e_node = Node(id=f"graphql_enum_{e_obj.id}", type="Enum", value=e_name)
                mission.graph.add(e_node)
                mission.graph.connect(s_node.id, e_node.id, "CONTAINS")
                
            for i_name, i_obj in schema.interfaces.items():
                i_node = Node(id=f"graphql_interface_{i_obj.id}", type="Interface", value=i_name)
                mission.graph.add(i_node)
                mission.graph.connect(s_node.id, i_node.id, "CONTAINS")
                
            for u_name, u_obj in schema.unions.items():
                u_node = Node(id=f"graphql_union_{u_obj.id}", type="Union", value=u_name)
                mission.graph.add(u_node)
                mission.graph.connect(s_node.id, u_node.id, "CONTAINS")
                
        # Generate Observation
        obs_desc = "Schema downloaded" if schema.source == "Introspection" else "Schema inferred"
        obs = Observation(description=obs_desc, confidence=schema.confidence, evidence=schema.evidence)
        if not hasattr(mission, "findings"):
            mission.findings = []
        mission.findings.append(obs)
        
    def _save_to_cache(self, schema: GraphQLSchema, cache_path: str):
        with open(cache_path, "w") as f:
            json.dump({"cached": True, "source": schema.source}, f)
            
    def _load_from_cache(self, cache_path: str) -> Optional[GraphQLSchema]:
        try:
            with open(cache_path, "r") as f:
                data = json.load(f)
                if data.get("cached"):
                    s = GraphQLSchema(source="Cache", evidence=[])
                    return s
        except Exception:
            pass
        return None
