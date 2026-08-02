import logging
import re
from typing import List, Dict, Any, Tuple

from argus.plugins.javascript.models import (
    JavaScriptASTNode, 
    JavaScriptModule, 
    JavaScriptSymbol,
    JavaScriptObservation,
    JavaScriptRoute,
    JavaScriptFramework,
    JavaScriptWebSocket
)

logger = logging.getLogger(__name__)

class JavaScriptParser:
    """
    Heuristic parser to extract AST-like structures and symbols from JavaScript.
    Productionized to use pre-compiled class-level regex patterns and inline 
    deduplication for improved performance and reduced memory overhead during 
    large bundle parsing.
    """

    # Regex patterns for heuristic extraction (compiled once at module load)
    func_pattern = re.compile(r'''function\s+([a-zA-Z_$][0-9a-zA-Z_$]*)\s*\(''')
    arrow_func_pattern = re.compile(r'''(?:const|let|var)\s+([a-zA-Z_$][0-9a-zA-Z_$]*)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_$][0-9a-zA-Z_$]*)\s*=>''')
    class_pattern = re.compile(r'''class\s+([a-zA-Z_$][0-9a-zA-Z_$]*)''')
    import_pattern = re.compile(r'''import\s+(?:.*?\s+from\s+)?['"]([^'"]+)['"]''')
    require_pattern = re.compile(r'''require\(['"]([^'"]+)['"]\)''')
    export_pattern = re.compile(r'''export\s+(?:default\s+)?(?:const|let|var|function|class)\s+([a-zA-Z_$][0-9a-zA-Z_$]*)''')
    export_default_pattern = re.compile(r'''export\s+default\s+([a-zA-Z_$][0-9a-zA-Z_$]*)''')
    const_pattern = re.compile(r'''const\s+([a-zA-Z_$][0-9a-zA-Z_$]*)\s*=''')
    
    # Objects and Configuration
    object_pattern = re.compile(r'''(?:const|let|var)\s+([a-zA-Z_$][0-9a-zA-Z_$]*)\s*=\s*{''')
    config_pattern = re.compile(r'''(?:const|let|var|export\s+const)\s+([a-zA-Z_$][0-9a-zA-Z_$]*[cC]onfig(?:uration)?|[a-zA-Z_$][0-9a-zA-Z_$]*[oO]ptions)\s*=''')
    
    # Env variables and feature flags
    env_pattern = re.compile(r'''(?:process\.env\.|import\.meta\.env\.)([a-zA-Z_$][0-9a-zA-Z_$]*)''')
    next_react_env_pattern = re.compile(r'''\b((?:NEXT_PUBLIC_|REACT_APP_|VITE_)[a-zA-Z0-9_]+)\b''')
    feature_flag_pattern = re.compile(r'''\b((?:ENABLE|FEATURE|IS|SHOULD|USE)_[A-Z0-9_]+)\b''')
    
    # Bundler and framework detection patterns
    webpack_pattern = re.compile(r'''(?:webpackJsonp|__webpack_require__|webpackChunk)''')
    nextjs_pattern = re.compile(r'''(?:_next/|__NEXT_DATA__|next/router|next/link)''')
    vite_pattern = re.compile(r'''(?:__vite_ssr__|import\.meta\.glob|vite/client)''')
    rollup_pattern = re.compile(r'''(?:System\.register\(|rollup-plugin)''')

    # PR4 Frameworks
    react_pattern = re.compile(r'''(?:import React|React\.createElement|useState|useEffect)''')
    vue_pattern = re.compile(r'''(?:import Vue|new Vue|defineComponent)''')
    nuxt_pattern = re.compile(r'''(?:__NUXT__|useFetch|defineNuxtConfig)''')
    angular_pattern = re.compile(r'''(?:@angular/core|NgModule|Component\()''')
    svelte_pattern = re.compile(r'''(?:svelte/internal|export let|onMount)''')
    remix_pattern = re.compile(r'''(?:@remix-run|useLoaderData|useActionData)''')
    astro_pattern = re.compile(r'''(?:Astro\.|getStaticPaths)''')
    solid_pattern = re.compile(r'''(?:solid-js|createSignal|createEffect)''')

    # PR4 Routing & Websocket
    client_route_pattern = re.compile(r'''(?:<Route\s+path=['"]([^'"]+)['"]|path:\s*['"]([^'"]+)['"])''')
    middleware_pattern = re.compile(r'''(?:export function middleware|app\.use)''')
    navigation_pattern = re.compile(r'''(?:router\.push\(['"]([^'"]+)['"]\)|navigate\(['"]([^'"]+)['"]\)|<Link\s+to=['"]([^'"]+)['"])''')
    service_worker_pattern = re.compile(r'''(?:navigator\.serviceWorker\.register\(['"]([^'"]+)['"]\))''')
    websocket_pattern = re.compile(r'''(?:new WebSocket\(['"]([^'"]+)['"]\)|io\(['"]([^'"]+)['"]\)|wss?://[^'"]+)''')

    # PR5 App Intel
    rest_pattern = re.compile(r'''(?:axios\.(?:get|post|put|delete|patch)\(['"]([^'"]+)['"]|fetch\(['"]([^'"]+)['"])''')
    graphql_pattern = re.compile(r'''(?:ApolloClient|useQuery|useMutation|graphql\s*`|\.graphql|/graphql)''')
    grpc_pattern = re.compile(r'''(?:@grpc/grpc-js|\.proto|grpc\.)''')
    third_party_api_pattern = re.compile(r'''(?:https://api\.stripe\.com|https://api\.github\.com|https://api\.twilio\.com|https://api\.sendgrid\.com)''')
    auth_provider_pattern = re.compile(r'''(?:Auth0|Firebase|Cognito|Okta|Clerk|Supabase\s+Auth)''')
    oauth_provider_pattern = re.compile(r'''(?:GoogleAuthProvider|FacebookAuthProvider|GithubAuthProvider|signInWith(?:Google|Facebook|Github|Twitter|Apple))''')
    type_pattern = re.compile(r'''(?:interface|type)\s+([a-zA-Z_$][0-9a-zA-Z_$]*)''')
    business_workflow_pattern = re.compile(r'''(?:function\s+((?:submit|process|handle|execute|start)(?:Payment|Checkout|Order|Transaction|Refund)[a-zA-Z0-9_]*)\s*\(|(?:const|let|var)\s+((?:submit|process|handle|execute|start)(?:Payment|Checkout|Order|Transaction|Refund)[a-zA-Z0-9_]*)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_$][0-9a-zA-Z_$]*)\s*=>)''')

    def parse(self, content: str, source: str) -> Tuple[List[Any], List[Any], List[Any], List[Any], List[Any], List[Any]]:
        """
        Parses JavaScript content to extract modules, symbols, routes, frameworks, and websockets.
        Optimized for memory efficiency by performing inline deduplication.
        """
        ast_nodes = []
        unique_modules = {}
        unique_symbols = {}
        unique_routes = {}
        unique_frameworks = {}
        websockets = []
        
        if not content:
            return ast_nodes, list(unique_modules.values()), list(unique_symbols.values()), list(unique_routes.values()), list(unique_frameworks.values()), websockets

        def _add_symbol(name, s_type):
            key = f"{name}_{s_type}"
            if key not in unique_symbols:
                unique_symbols[key] = JavaScriptSymbol(name=name, symbol_type=s_type, source=source)
                
        def _add_route(path, r_type):
            key = f"{path}_{r_type}"
            if key not in unique_routes:
                unique_routes[key] = JavaScriptRoute(path=path, route_type=r_type, source=source)
                
        def _add_framework(name):
            if name not in unique_frameworks:
                unique_frameworks[name] = JavaScriptFramework(name=name, source=source)

        # Determine module type based on content heuristics
        module_type = "CommonJS"
        if "import " in content or "export " in content:
            module_type = "ES Modules"
            
        if self.nextjs_pattern.search(content):
            module_type = "Next.js"
            _add_framework("Next.js")
        elif self.vite_pattern.search(content):
            module_type = "Vite"
        elif self.webpack_pattern.search(content):
            module_type = "Webpack bundles"
        elif self.rollup_pattern.search(content):
            module_type = "Rollup"

        # Framework detection
        if self.react_pattern.search(content) and "Next.js" not in unique_frameworks:
            _add_framework("React")
        if self.vue_pattern.search(content):
            _add_framework("Vue")
        if self.nuxt_pattern.search(content):
            _add_framework("Nuxt")
        if self.angular_pattern.search(content):
            _add_framework("Angular")
        if self.svelte_pattern.search(content):
            _add_framework("Svelte")
        if self.remix_pattern.search(content):
            _add_framework("Remix")
        if self.astro_pattern.search(content):
            _add_framework("Astro")
        if self.solid_pattern.search(content):
            _add_framework("Solid")

        # Client / Dynamic Routes
        for match in self.client_route_pattern.finditer(content):
            path = match.group(1) or match.group(2)
            if path:
                r_type = "Dynamic" if (':' in path or '[' in path) else "Client"
                _add_route(path, r_type)
                
        # Middleware
        if self.middleware_pattern.search(content):
            _add_route("middleware", "Middleware")
            
        # Navigation
        for match in self.navigation_pattern.finditer(content):
            path = match.group(1) or match.group(2) or match.group(3)
            if path:
                _add_route(path, "Navigation")

        # Service Workers
        for match in self.service_worker_pattern.finditer(content):
            path = match.group(1)
            if path:
                _add_symbol(path, "ServiceWorker")

        # WebSockets
        for match in self.websocket_pattern.finditer(content):
            ws = match.group(1) or match.group(2) or match.group(0)
            websockets.append(JavaScriptWebSocket(url=ws, source=source))

        # PR5 Extracted Symbols
        for match in self.rest_pattern.finditer(content):
            ep = match.group(1) or match.group(2)
            if ep:
                _add_symbol(ep, "RESTEndpoint")
                
        if self.graphql_pattern.search(content):
            _add_symbol("GraphQL Detected", "GraphQLEndpoint")
            
        if self.grpc_pattern.search(content):
            _add_symbol("gRPC Detected", "gRPCReference")
            
        for match in self.third_party_api_pattern.finditer(content):
            _add_symbol(match.group(0), "ThirdPartyAPI")
            
        for match in self.auth_provider_pattern.finditer(content):
            _add_symbol(match.group(0), "AuthProvider")
            
        for match in self.oauth_provider_pattern.finditer(content):
            _add_symbol(match.group(0), "OAuthProvider")
            
        for match in self.type_pattern.finditer(content):
            _add_symbol(match.group(1), "Object")

        for match in self.business_workflow_pattern.finditer(content):
            wf = match.group(1) or match.group(2)
            if wf:
                _add_symbol(wf, "BusinessWorkflow")

        # 1. Imports (Modules)
        imports = []
        for match in self.import_pattern.finditer(content):
            imports.append(match.group(1))
            _add_symbol(match.group(1), "Import")
            
        for match in self.require_pattern.finditer(content):
            imports.append(match.group(1))
            _add_symbol(match.group(1), "Import")

        if imports or module_type != "CommonJS":
            unique_modules[source] = JavaScriptModule(name=source, module_type=module_type, imports=imports, source=source)

        # 2. Exports
        for match in self.export_pattern.finditer(content):
            _add_symbol(match.group(1), "Export")
        for match in self.export_default_pattern.finditer(content):
            _add_symbol(match.group(1), "Export")

        # 3. Functions
        for match in self.func_pattern.finditer(content):
            _add_symbol(match.group(1), "Function")
            ast_nodes.append(JavaScriptASTNode(node_type="FunctionDeclaration", value=match.group(1), source=source))
            
        for match in self.arrow_func_pattern.finditer(content):
            _add_symbol(match.group(1), "Function")
            ast_nodes.append(JavaScriptASTNode(node_type="VariableDeclaration", value=match.group(1), source=source))

        # 4. Classes
        for match in self.class_pattern.finditer(content):
            _add_symbol(match.group(1), "Class")
            ast_nodes.append(JavaScriptASTNode(node_type="ClassDeclaration", value=match.group(1), source=source))

        # 5. Constants
        for match in self.const_pattern.finditer(content):
            _add_symbol(match.group(1), "Constant")
            
        # 6. Objects and Configurations
        for match in self.object_pattern.finditer(content):
            _add_symbol(match.group(1), "Object")
            
        for match in self.config_pattern.finditer(content):
            _add_symbol(match.group(1), "Configuration")

        # 7. Environment Variables
        for match in self.env_pattern.finditer(content):
            _add_symbol(match.group(1), "EnvVar")
            
        for match in self.next_react_env_pattern.finditer(content):
            _add_symbol(match.group(1), "EnvVar")

        # 8. Feature Flags
        for match in self.feature_flag_pattern.finditer(content):
            _add_symbol(match.group(1), "FeatureFlag")

        return ast_nodes, list(unique_modules.values()), list(unique_symbols.values()), list(unique_routes.values()), list(unique_frameworks.values()), websockets
